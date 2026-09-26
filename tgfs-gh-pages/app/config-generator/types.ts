// Shared shapes of the config generator's form state.

import { EncryptionConfig } from "./components/EncryptionField";

export type MetadataType = "pinned_message" | "github_repo";

export interface ChannelConfig {
  id: string;
  name: string;
  type: MetadataType;
  mirrors: string[];
  github_repo?: {
    repo: string;
    commit: string;
    access_token: string;
  };
}

export interface RedundancyConfig {
  enabled: boolean;
  mode: "forward" | "reupload";
  strict: boolean;
}

export interface UserConfig {
  username: string;
  password: string;
  readonly: boolean;
}

export interface SftpConfig {
  enabled: boolean;
  host: string;
  port: number;
  host_key_file: string;
  authorized_keys_dir: string;
  upload_buffer_size_mb: number;
}

export interface TransferConfig {
  // UI only: when off, no transfer block is written at all and the
  // application falls back to its own defaults.
  enabled: boolean;
  upload_workers_small: number;
  upload_workers_big: number;
  upload_part_size_kb: number;
  download_piece_size_kb: number;
  download_pieces_in_flight: number;
  parallel_download_threshold_mb: number;
  connection_pool_size: number;
  chunk_cache_mb: number;
  chunk_cache_readahead: number;
  chunk_cache_block_kb: number;
}

export interface ConfigData {
  telegram: {
    api_id: string;
    api_hash: string;
    lib: "pyrogram" | "telethon";
    account: {
      session_file: string;
    };
    bot: {
      session_file: string;
      tokens: string[];
    };
    channels: ChannelConfig[];
  };
  tgfs: {
    users: UserConfig[];
    jwt: {
      secret: string;
      algorithm: string;
      life: number;
    };
    server: {
      host: string;
      port: number;
    };
    sftp: SftpConfig;
    transfer: TransferConfig;
    encryption: EncryptionConfig;
  };
}

export const newChannel = (name: string): ChannelConfig => ({
  id: "",
  name,
  type: "pinned_message",
  mirrors: [],
  github_repo: {
    repo: "",
    commit: "master",
    access_token: "",
  },
});

// The form as it opens: one channel and the loader's defaults everywhere
// else. A fresh object every time, so a loaded config never shares nested
// state with the initial one.
export const defaultConfig = (): ConfigData => ({
  telegram: {
    api_id: "",
    api_hash: "",
    lib: "telethon",
    account: {
      session_file: "account.session",
    },
    bot: {
      session_file: "bot.session",
      tokens: [""],
    },
    channels: [newChannel("default")],
  },
  tgfs: {
    users: [
      {
        username: "user",
        password: "password",
        readonly: false,
      },
    ],
    jwt: {
      secret: "",
      algorithm: "HS256",
      life: 604800,
    },
    server: {
      host: "0.0.0.0",
      port: 1900,
    },
    sftp: {
      enabled: false,
      host: "0.0.0.0",
      port: 2222,
      host_key_file: "sftp_host_key",
      authorized_keys_dir: "",
      upload_buffer_size_mb: 64,
    },
    transfer: {
      enabled: false,
      upload_workers_small: 3,
      upload_workers_big: 8,
      upload_part_size_kb: 512,
      download_piece_size_kb: 4096,
      download_pieces_in_flight: 4,
      parallel_download_threshold_mb: 10,
      connection_pool_size: 1,
      chunk_cache_mb: 0,
      chunk_cache_readahead: 2,
      chunk_cache_block_kb: 1024,
    },
    encryption: {
      enabled: false,
      encrypt_names: false,
      passphrase_source: "passphrase_env",
      passphrase: "",
      passphrase_env: "TGFS_MASTER_PASSPHRASE",
      passphrase_file: "secrets/master.passphrase",
      master_salt_file: "master.salt",
      chunk_size: 65536,
    },
  },
});
