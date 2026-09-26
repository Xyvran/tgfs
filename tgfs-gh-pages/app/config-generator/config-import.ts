// Reads an existing config.yaml back into the form.
//
// Follows the loader (tgfs/config.py): a top-level ``telegram`` block with
// ``private_file_channel`` and ``redundancy``, and a ``tgfs`` block whose
// ``metadata`` is keyed by channel. Anything the form has no field for is
// reported in ``notes`` instead of being dropped silently.

import yaml from "js-yaml";
import {
  EncryptionConfig,
  PassphraseSource,
} from "./components/EncryptionField";
import {
  ChannelConfig,
  ConfigData,
  MetadataType,
  RedundancyConfig,
  TransferConfig,
  UserConfig,
  defaultConfig,
  newChannel,
} from "./types";

export interface ImportedConfig {
  config: ConfigData;
  redundancy: RedundancyConfig;
  withUserAccountUpload: boolean;
  withUserAccountDownload: boolean;
  // What the form could not take over, one line each.
  notes: string[];
}

type Mapping = Record<string, unknown>;

// The file is parsed with the failsafe schema, so every scalar arrives as
// a string (or null for an empty value). That keeps a channel id intact
// however long it is; the typed accessors below convert what the form
// stores as numbers and booleans. Truthy words follow PyYAML, which the
// server parses with.
const isMapping = (value: unknown): value is Mapping =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const asMapping = (value: unknown): Mapping =>
  isMapping(value) ? value : {};

const asString = (value: unknown, fallback = ""): string =>
  typeof value === "string" ? value : fallback;

const asNumber = (value: unknown, fallback: number): number => {
  const text = asString(value).trim();
  const number = Number(text);
  return text !== "" && Number.isFinite(number) ? number : fallback;
};

const asBoolean = (value: unknown, fallback: boolean): boolean => {
  const text = asString(value).trim().toLowerCase();
  if (["true", "yes", "on"].includes(text)) return true;
  if (["false", "no", "off"].includes(text)) return false;
  return fallback;
};

const asList = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return value.map((item) => asString(item).trim()).filter((s) => s !== "");
  }
  const single = asString(value).trim();
  return single !== "" ? [single] : [];
};

class Notes {
  readonly lines: string[] = [];

  add(line: string) {
    if (!this.lines.includes(line)) this.lines.push(line);
  }

  // Report every key the form has no field for.
  unknownKeys(path: string, mapping: Mapping, known: string[]) {
    Object.keys(mapping)
      .filter((key) => !known.includes(key))
      .forEach((key) =>
        this.add(`${path}.${key} is not part of this form and was left out`)
      );
  }

  // A choice outside the allowed values falls back and is reported.
  choice<T extends string>(
    path: string,
    value: unknown,
    allowed: readonly T[],
    fallback: T
  ): T {
    if (value === null || value === undefined) return fallback;
    const text = asString(value);
    if ((allowed as readonly string[]).includes(text)) return text as T;
    this.add(`${path}: unknown value '${text}', using '${fallback}'`);
    return fallback;
  }
}

const METADATA_TYPES: readonly MetadataType[] = ["pinned_message", "github_repo"];

// ``telegram.private_file_channel`` lists the channels,
// ``tgfs.metadata[<channel>]`` names each one and
// ``telegram.redundancy.mirrors[<channel>]`` lists its mirrors.
const readChannels = (
  telegram: Mapping,
  app: Mapping,
  notes: Notes
): { channels: ChannelConfig[]; redundancy: RedundancyConfig } => {
  const redundancyData = asMapping(telegram.redundancy);
  notes.unknownKeys("telegram.redundancy", redundancyData, [
    "mirrors",
    "mode",
    "strict",
  ]);
  const mirrorMap = asMapping(redundancyData.mirrors);
  const redundancy: RedundancyConfig = {
    enabled: false,
    mode: notes.choice(
      "telegram.redundancy.mode",
      redundancyData.mode,
      ["forward", "reupload"] as const,
      "forward"
    ),
    strict: asBoolean(redundancyData.strict, false),
  };

  const ids = asList(telegram.private_file_channel);
  if (ids.length === 0) {
    notes.add(
      "telegram.private_file_channel is empty; the channel list was left as it was"
    );
    return { channels: defaultConfig().telegram.channels, redundancy };
  }

  const metadataMap = asMapping(app.metadata);
  // A very old single-channel config keeps ``metadata: {type, ...}``
  // without the channel key; it belongs to the only channel.
  const singleForm = "type" in metadataMap && ids.length === 1;

  const channels = ids.map((id) => {
    const meta = singleForm ? metadataMap : asMapping(metadataMap[id]);
    const path = `tgfs.metadata.${id}`;
    if (!singleForm && !isMapping(metadataMap[id])) {
      notes.add(`${path} is missing; the channel was named after its id`);
    }
    notes.unknownKeys(path, meta, ["name", "type", "github_repo"]);
    const github = asMapping(meta.github_repo);
    const channel = newChannel(asString(meta.name, singleForm ? "default" : id));
    channel.id = id;
    channel.type = notes.choice(
      `${path}.type`,
      meta.type,
      METADATA_TYPES,
      "pinned_message"
    );
    channel.mirrors = asList(mirrorMap[id]).filter((m) => m !== id);
    channel.github_repo = {
      repo: asString(github.repo),
      commit: asString(github.commit, "master"),
      access_token: asString(github.access_token),
    };
    if (channel.mirrors.length > 0) redundancy.enabled = true;
    return channel;
  });

  return { channels, redundancy };
};

const readUsers = (raw: unknown, notes: Notes): UserConfig[] => {
  const users = Object.entries(asMapping(raw)).map(([username, value]) => {
    const data = asMapping(value);
    notes.unknownKeys(`tgfs.users.${username}`, data, ["password", "readonly"]);
    return {
      username,
      password: asString(data.password),
      readonly: asBoolean(data.readonly, false),
    };
  });
  return users.length > 0
    ? users
    : [{ username: "", password: "", readonly: false }];
};

const readTransfer = (
  raw: unknown,
  fallback: TransferConfig,
  notes: Notes
): TransferConfig => {
  if (!isMapping(raw)) return fallback;
  const keys = (Object.keys(fallback) as (keyof TransferConfig)[]).filter(
    (key) => key !== "enabled"
  );
  notes.unknownKeys("tgfs.transfer", raw, keys);
  const transfer: TransferConfig = { ...fallback, enabled: true };
  keys.forEach((key) => {
    transfer[key] = asNumber(raw[key], fallback[key]);
  });
  return transfer;
};

const readEncryption = (
  raw: unknown,
  fallback: EncryptionConfig,
  notes: Notes
): EncryptionConfig => {
  if (!isMapping(raw)) return fallback;
  notes.unknownKeys("tgfs.encryption", raw, [
    "enabled",
    "encrypt_names",
    "passphrase",
    "passphrase_env",
    "passphrase_file",
    "master_salt_file",
    "chunk_size",
  ]);
  const passphrase = asString(raw.passphrase);
  const passphraseEnv = asString(raw.passphrase_env);
  const passphraseFile = asString(raw.passphrase_file);
  const source: PassphraseSource = passphrase
    ? "passphrase"
    : passphraseFile
    ? "passphrase_file"
    : "passphrase_env";
  return {
    enabled: asBoolean(raw.enabled, false),
    encrypt_names: asBoolean(raw.encrypt_names, false),
    passphrase_source: source,
    passphrase,
    passphrase_env: passphraseEnv || fallback.passphrase_env,
    passphrase_file: passphraseFile || fallback.passphrase_file,
    master_salt_file: asString(raw.master_salt_file, fallback.master_salt_file),
    chunk_size: asNumber(raw.chunk_size, fallback.chunk_size),
  };
};

export const importConfig = (text: string): ImportedConfig => {
  const doc = yaml.load(text, { schema: yaml.FAILSAFE_SCHEMA });
  if (!isMapping(doc)) {
    throw new Error("The file does not hold a YAML mapping");
  }
  if ("stores" in doc || "filesystems" in doc || "backends" in doc) {
    throw new Error(
      "This is a tgdcfs config (stores and file systems); tgfs lists its channels under telegram.private_file_channel"
    );
  }
  if (!isMapping(doc.tgfs)) {
    throw new Error("The configuration block 'tgfs' is missing");
  }
  const app = doc.tgfs;
  const notes = new Notes();
  const config = defaultConfig();
  notes.unknownKeys("", doc, ["telegram", "tgfs"]);

  const telegram = asMapping(doc.telegram);
  if (!isMapping(doc.telegram)) {
    notes.add("The configuration block 'telegram' is missing");
  }
  notes.unknownKeys("telegram", telegram, [
    "api_id",
    "api_hash",
    "lib",
    "account",
    "bot",
    "private_file_channel",
    "redundancy",
  ]);
  config.telegram.api_id = asString(telegram.api_id).trim();
  config.telegram.api_hash = asString(telegram.api_hash).trim();
  config.telegram.lib = notes.choice(
    "telegram.lib",
    telegram.lib,
    ["pyrogram", "telethon"] as const,
    "telethon"
  );
  const bot = asMapping(telegram.bot);
  notes.unknownKeys("telegram.bot", bot, ["token", "tokens", "session_file"]);
  const tokens = asList(bot.tokens);
  const single = asString(bot.token).trim();
  if (single) tokens.unshift(single);
  config.telegram.bot = {
    session_file: asString(bot.session_file, "bot.session"),
    tokens: tokens.length > 0 ? tokens : [""],
  };
  let withUserAccountUpload = false;
  let withUserAccountDownload = false;
  if (isMapping(telegram.account)) {
    notes.unknownKeys("telegram.account", telegram.account, [
      "session_file",
      "used_to_upload",
      "used_to_download",
    ]);
    withUserAccountUpload = asBoolean(telegram.account.used_to_upload, false);
    withUserAccountDownload = asBoolean(
      telegram.account.used_to_download,
      false
    );
  }

  const { channels, redundancy } = readChannels(telegram, app, notes);
  config.telegram.channels = channels;

  notes.unknownKeys("tgfs", app, [
    "users",
    "jwt",
    "metadata",
    "server",
    "sftp",
    "transfer",
    "encryption",
  ]);
  config.tgfs.users = readUsers(app.users, notes);

  const jwt = asMapping(app.jwt);
  notes.unknownKeys("tgfs.jwt", jwt, ["secret", "algorithm", "life"]);
  config.tgfs.jwt = {
    secret: asString(jwt.secret),
    algorithm: asString(jwt.algorithm, "HS256"),
    life: asNumber(jwt.life, 604800),
  };

  const server = asMapping(app.server);
  notes.unknownKeys("tgfs.server", server, ["host", "port"]);
  config.tgfs.server = {
    host: asString(server.host, config.tgfs.server.host),
    port: asNumber(server.port, config.tgfs.server.port),
  };

  if (isMapping(app.sftp)) {
    const sftp = app.sftp;
    notes.unknownKeys("tgfs.sftp", sftp, [
      "enabled",
      "host",
      "port",
      "host_key_file",
      "authorized_keys_dir",
      "upload_buffer_size_mb",
    ]);
    const fallback = config.tgfs.sftp;
    config.tgfs.sftp = {
      enabled: asBoolean(sftp.enabled, false),
      host: asString(sftp.host, fallback.host),
      port: asNumber(sftp.port, fallback.port),
      host_key_file: asString(sftp.host_key_file, fallback.host_key_file),
      authorized_keys_dir: asString(sftp.authorized_keys_dir),
      upload_buffer_size_mb: asNumber(
        sftp.upload_buffer_size_mb,
        fallback.upload_buffer_size_mb
      ),
    };
  }

  config.tgfs.transfer = readTransfer(app.transfer, config.tgfs.transfer, notes);
  config.tgfs.encryption = readEncryption(
    app.encryption,
    config.tgfs.encryption,
    notes
  );

  return {
    config,
    redundancy,
    withUserAccountUpload,
    withUserAccountDownload,
    notes: notes.lines,
  };
};
