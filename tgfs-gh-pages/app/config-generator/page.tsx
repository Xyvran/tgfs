"use client";

import { Add, ContentCopy, Download, Refresh } from "@mui/icons-material";
import {
  Alert,
  AlertTitle,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Container,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Typography,
} from "@mui/material";
import yaml from "js-yaml";
import { useCallback, useEffect, useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import { BotTokenField } from "./components/BotTokenField";
import { ChannelField } from "./components/ChannelField";
import { ConfigTextField } from "./components/ConfigTextField";
import {
  EncryptionConfig,
  EncryptionField,
} from "./components/EncryptionField";
import { FieldRow } from "./components/FieldRow";
import { FormSection } from "./components/FormSection";
import { UserField } from "./components/UserField";

interface ChannelConfig {
  id: string;
  name: string;
  type: "pinned_message" | "github_repo";
  mirrors: string[];
  github_repo?: {
    repo: string;
    commit: string;
    access_token: string;
  };
}

interface RedundancyConfig {
  enabled: boolean;
  mode: "forward" | "reupload";
  strict: boolean;
}

interface SftpConfig {
  enabled: boolean;
  host: string;
  port: number;
  host_key_file: string;
  authorized_keys_dir: string;
  upload_buffer_size_mb: number;
}

interface TransferConfig {
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

interface ConfigData {
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
    users: {
      username: string;
      password: string;
    }[];
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

// Type-safe path mapping for updateConfig
type ConfigUpdatePaths = {
  "telegram.api_id": string;
  "telegram.api_hash": string;
  "telegram.lib": "pyrogram" | "telethon";
  "telegram.channels": ChannelConfig[];
  "telegram.bot.tokens": string[];
  "tgfs.users": { username: string; password: string }[];
  "tgfs.jwt.secret": string;
  "tgfs.jwt.algorithm": string;
  "tgfs.jwt.life": number;
  "tgfs.server.host": string;
  "tgfs.server.port": number;
  "tgfs.sftp": SftpConfig;
  "tgfs.transfer": TransferConfig;
  "tgfs.encryption": EncryptionConfig;
};

const generateRandomSecret = (): string => {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
  let result = "";
  for (let i = 0; i < 64; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

export default function ConfigGenerator() {
  const [withUserAccountUpload, setWithUserAccountUpload] = useState(false);
  const [withUserAccountDownload, setWithUserAccountDownload] = useState(false);
  const [redundancy, setRedundancy] = useState<RedundancyConfig>({
    enabled: false,
    mode: "forward",
    strict: false,
  });

  const [config, setConfig] = useState<ConfigData>({
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
      channels: [
        {
          id: "",
          name: "default",
          type: "pinned_message",
          mirrors: [],
          github_repo: {
            repo: "",
            commit: "master",
            access_token: "",
          },
        },
      ],
    },
    tgfs: {
      users: [
        {
          username: "user",
          password: "password",
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

  const updateConfig = useCallback(
    <K extends keyof ConfigUpdatePaths>(
      path: K,
      value: ConfigUpdatePaths[K]
    ): void => {
      const newConfig = { ...config };

      if (path === "telegram.api_id") {
        newConfig.telegram.api_id = value as string;
      } else if (path === "telegram.api_hash") {
        newConfig.telegram.api_hash = value as string;
      } else if (path === "telegram.lib") {
        newConfig.telegram.lib = value as "pyrogram" | "telethon";
      } else if (path === "telegram.channels") {
        newConfig.telegram.channels = value as ChannelConfig[];
      } else if (path === "telegram.bot.tokens") {
        newConfig.telegram.bot.tokens = value as string[];
      } else if (path === "tgfs.users") {
        newConfig.tgfs.users = value as {
          username: string;
          password: string;
        }[];
      } else if (path === "tgfs.jwt.secret") {
        newConfig.tgfs.jwt.secret = value as string;
      } else if (path === "tgfs.jwt.algorithm") {
        newConfig.tgfs.jwt.algorithm = value as string;
      } else if (path === "tgfs.jwt.life") {
        newConfig.tgfs.jwt.life = value as number;
      } else if (path === "tgfs.server.host") {
        newConfig.tgfs.server.host = value as string;
      } else if (path === "tgfs.server.port") {
        newConfig.tgfs.server.port = value as number;
      } else if (path === "tgfs.sftp") {
        newConfig.tgfs.sftp = value as SftpConfig;
      } else if (path === "tgfs.transfer") {
        newConfig.tgfs.transfer = value as TransferConfig;
      } else if (path === "tgfs.encryption") {
        newConfig.tgfs.encryption = value as EncryptionConfig;
      }

      setConfig(newConfig);
    },
    [config]
  );

  // Generate JWT secret on client side only to avoid hydration mismatch
  useEffect(() => {
    if (config.tgfs.jwt.secret === "") {
      updateConfig("tgfs.jwt.secret", generateRandomSecret());
    }
  }, [config.tgfs.jwt.secret, updateConfig]);

  const addBotToken = () => {
    const newTokens = [...config.telegram.bot.tokens, ""];
    updateConfig("telegram.bot.tokens", newTokens);
  };

  const removeBotToken = (index: number) => {
    const newTokens = config.telegram.bot.tokens.filter((_, i) => i !== index);
    updateConfig("telegram.bot.tokens", newTokens);
  };

  const updateBotToken = (index: number, value: string) => {
    const newTokens = [...config.telegram.bot.tokens];
    newTokens[index] = value;
    updateConfig("telegram.bot.tokens", newTokens);
  };

  const generateYaml = () => {
    // Build metadata object from channels
    const metadata: {
      [channelId: string]: {
        name: string;
        type: "pinned_message" | "github_repo";
        github_repo?: {
          repo: string;
          commit: string;
          access_token: string;
        };
      };
    } = {};
    config.telegram.channels
      .filter((channel) => channel.id.trim() !== "")
      .forEach((channel) => {
        metadata[channel.id] = {
          name: channel.name,
          type: channel.type,
          ...(channel.type === "github_repo" && channel.github_repo
            ? { github_repo: channel.github_repo }
            : {}),
        };
      });

    const configForYaml = {
      telegram: {
        api_id: config.telegram.api_id,
        api_hash: config.telegram.api_hash,
        lib: config.telegram.lib,
        ...(withUserAccountUpload ||
          withUserAccountDownload ||
          Object.values(metadata).some(
            (channel) => channel.type === "pinned_message"
          )
          ? {
            account: {
              session_file: "account.session",
              used_to_upload: withUserAccountUpload,
              used_to_download: withUserAccountDownload,
            },
          }
          : {}),
        bot: {
          session_file: config.telegram.bot.session_file,
          tokens: config.telegram.bot.tokens.filter(
            (token) => token.trim() !== ""
          ),
        },
        private_file_channel: config.telegram.channels
          .filter((channel) => channel.id.trim() !== "")
          .map((channel) => channel.id),
        ...(() => {
          if (!redundancy.enabled) return {};
          const mirrors: { [channelId: string]: string[] } = {};
          config.telegram.channels
            .filter((channel) => channel.id.trim() !== "")
            .forEach((channel) => {
              const mirrorIds = (channel.mirrors || [])
                .map((m) => m.trim())
                .filter((m) => m !== "" && m !== channel.id.trim());
              if (mirrorIds.length > 0) {
                mirrors[channel.id] = mirrorIds;
              }
            });
          if (Object.keys(mirrors).length === 0) return {};
          return {
            redundancy: {
              mirrors,
              mode: redundancy.mode,
              strict: redundancy.strict,
            },
          };
        })(),
      },
      tgfs: {
        users: config.tgfs.users.reduce((acc, user) => {
          if (user.username.trim() !== "") {
            acc[user.username] = { password: user.password };
          }
          return acc;
        }, {} as { [key: string]: { password: string } }),
        jwt: config.tgfs.jwt,
        metadata,
        server: config.tgfs.server,
        ...(() => {
          const sftp = config.tgfs.sftp;
          if (!sftp.enabled) return {};
          const block: {
            enabled: boolean;
            host: string;
            port: number;
            host_key_file: string;
            authorized_keys_dir?: string;
            upload_buffer_size_mb: number;
          } = {
            enabled: true,
            host: sftp.host,
            port: sftp.port,
            host_key_file: sftp.host_key_file,
            upload_buffer_size_mb: sftp.upload_buffer_size_mb,
          };
          if (sftp.authorized_keys_dir.trim() !== "") {
            block.authorized_keys_dir = sftp.authorized_keys_dir.trim();
          }
          return { sftp: block };
        })(),
        ...(() => {
          const transfer = config.tgfs.transfer;
          if (!transfer.enabled) return {};
          // "enabled" only drives this form; it is not a config key.
          const settings = { ...transfer } as Partial<TransferConfig>;
          delete settings.enabled;
          return { transfer: settings };
        })(),
        encryption: (() => {
          const enc = config.tgfs.encryption;
          const block: {
            enabled: boolean;
            encrypt_names: boolean;
            passphrase?: string;
            passphrase_env?: string;
            passphrase_file?: string;
            master_salt_file: string;
            chunk_size: number;
          } = {
            enabled: enc.enabled,
            encrypt_names: enc.encrypt_names,
            master_salt_file: enc.master_salt_file,
            chunk_size: enc.chunk_size,
          };
          if (enc.enabled) {
            if (enc.passphrase_source === "passphrase") {
              block.passphrase = enc.passphrase;
            } else if (enc.passphrase_source === "passphrase_env") {
              block.passphrase_env = enc.passphrase_env;
            } else if (enc.passphrase_source === "passphrase_file") {
              block.passphrase_file = enc.passphrase_file;
            }
          }
          return block;
        })(),
      },
    };

    return yaml.dump(configForYaml, { indent: 2 });
  };

  const downloadConfig = () => {
    const yamlContent = generateYaml();
    const blob = new Blob([yamlContent], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "config.yaml";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = () => {
    const yamlContent = generateYaml();
    navigator.clipboard.writeText(yamlContent);
  };

  const regenerateJwtSecret = () => {
    updateConfig("tgfs.jwt.secret", generateRandomSecret());
  };

  const addUser = () => {
    const newUsers = [...config.tgfs.users, { username: "", password: "" }];
    updateConfig("tgfs.users", newUsers);
  };

  const removeUser = (index: number) => {
    const newUsers = config.tgfs.users.filter((_, i) => i !== index);
    updateConfig("tgfs.users", newUsers);
  };

  const updateUser = (
    index: number,
    field: "username" | "password",
    value: string
  ) => {
    const newUsers = [...config.tgfs.users];
    newUsers[index][field] = value;
    updateConfig("tgfs.users", newUsers);
  };

  const addChannel = () => {
    const newChannels = [
      ...config.telegram.channels,
      {
        id: "",
        name: `channel-${config.telegram.channels.length + 1}`,
        type: "pinned_message" as const,
        mirrors: [],
        github_repo: {
          repo: "",
          commit: "master",
          access_token: "",
        },
      },
    ];
    updateConfig("telegram.channels", newChannels);
  };

  const addMirror = (channelIndex: number) => {
    const newChannels = [...config.telegram.channels];
    newChannels[channelIndex].mirrors = [
      ...(newChannels[channelIndex].mirrors || []),
      "",
    ];
    updateConfig("telegram.channels", newChannels);
  };

  const removeMirror = (channelIndex: number, mirrorIndex: number) => {
    const newChannels = [...config.telegram.channels];
    newChannels[channelIndex].mirrors = newChannels[
      channelIndex
    ].mirrors.filter((_, i) => i !== mirrorIndex);
    updateConfig("telegram.channels", newChannels);
  };

  const updateMirror = (
    channelIndex: number,
    mirrorIndex: number,
    value: string
  ) => {
    const newChannels = [...config.telegram.channels];
    const mirrors = [...newChannels[channelIndex].mirrors];
    mirrors[mirrorIndex] = value;
    newChannels[channelIndex].mirrors = mirrors;
    updateConfig("telegram.channels", newChannels);
  };

  const getMirrorErrors = (channelIndex: number): string[][] => {
    const channel = config.telegram.channels[channelIndex];
    const primaryIds = config.telegram.channels
      .map((c) => c.id.trim())
      .filter((id) => id !== "");
    return (channel.mirrors || []).map((mirror, mirrorIndex) => {
      const errors: string[] = [];
      const value = mirror.trim();
      if (!value) {
        errors.push("Mirror channel ID is required (or remove this row)");
        return errors;
      }
      if (value === channel.id.trim()) {
        errors.push("A channel cannot mirror itself");
      }
      if (
        (channel.mirrors || []).findIndex(
          (m, i) => i !== mirrorIndex && m.trim() === value
        ) !== -1
      ) {
        errors.push("Duplicate mirror channel");
      }
      if (primaryIds.includes(value)) {
        errors.push(
          "This ID is also used as a primary file channel — a mirror " +
          "should be a dedicated channel"
        );
      }
      return errors;
    });
  };

  const removeChannel = (index: number) => {
    const newChannels = config.telegram.channels.filter((_, i) => i !== index);
    updateConfig("telegram.channels", newChannels);
  };

  // Validation functions
  const isValidDirectoryName = (name: string): boolean => {
    // Valid directory name: no / \ : * ? " < > | and not . or ..
    const invalidChars = /[\/\\:*?"<>|]/;
    return (
      !invalidChars.test(name) &&
      name !== "." &&
      name !== ".." &&
      name.trim().length > 0
    );
  };

  const getChannelNameErrors = (index: number, name: string): string[] => {
    const errors: string[] = [];

    if (!name.trim()) {
      errors.push("Display name is required");
    } else {
      if (!isValidDirectoryName(name)) {
        errors.push('Invalid characters. Cannot contain: / \\ : * ? " < > |');
      }

      // Check for duplicates
      const duplicateIndex = config.telegram.channels.findIndex(
        (channel, i) =>
          i !== index &&
          channel.name.trim().toLowerCase() === name.trim().toLowerCase()
      );
      if (duplicateIndex !== -1) {
        errors.push("Display name must be unique across channels");
      }
    }

    return errors;
  };

  const updateChannel = (
    index: number,
    field: "id" | "name" | "type",
    value: string
  ) => {
    const newChannels = [...config.telegram.channels];
    if (field === "id" || field === "name") {
      newChannels[index][field] = value;
    } else if (field === "type") {
      newChannels[index][field] = value as "pinned_message" | "github_repo";
    }
    updateConfig("telegram.channels", newChannels);
  };

  const updateChannelGitHubRepo = (
    channelIndex: number,
    field: keyof NonNullable<ChannelConfig["github_repo"]>,
    value: string
  ) => {
    const newChannels = [...config.telegram.channels];
    if (!newChannels[channelIndex].github_repo) {
      newChannels[channelIndex].github_repo = {
        repo: "",
        commit: "master",
        access_token: "",
      };
    }
    newChannels[channelIndex].github_repo![field] = value;
    updateConfig("telegram.channels", newChannels);
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Typography variant="h3" component="h1" gutterBottom align="center">
        TGFS Config Generator
      </Typography>

      <Typography
        variant="h6"
        color="text.secondary"
        align="center"
        sx={{ mb: 4 }}
      >
        Generate your TGFS configuration file with this interactive form
      </Typography>

      <Alert severity="warning" sx={{ mb: 3 }}>
        <AlertTitle>Important</AlertTitle>
        Keep your API credentials and bot tokens secure. Never share them
        publicly.
      </Alert>

      <Box
        sx={{
          display: "flex",
          gap: 3,
          flexDirection: { xs: "column", md: "row" },
        }}
      >
        <Box sx={{ flex: 1 }}>
          <Paper sx={{ p: 3 }}>
            <FormSection title="Telegram" showDivider={false}>
              <Box
                sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}
              >
                <Typography variant="h6">API Credentials</Typography>
                <Button
                  variant="outlined"
                  size="small"
                  component="a"
                  href="https://my.telegram.org/apps"
                  target="_blank"
                  rel="noopener noreferrer"
                  sx={{ textTransform: "none" }}
                >
                  Get API Keys
                </Button>
              </Box>
              <FieldRow justifyContent="space-between">
                <ConfigTextField
                  label="API ID"
                  value={config.telegram.api_id}
                  onChange={(e) =>
                    updateConfig("telegram.api_id", e.target.value)
                  }
                  style={{ flex: 1 }}
                  required
                />
                <ConfigTextField
                  label="API Hash"
                  value={config.telegram.api_hash}
                  onChange={(e) =>
                    updateConfig("telegram.api_hash", e.target.value)
                  }
                  style={{ flex: 1 }}
                  required
                />
                <FormControl size="small" sx={{ minWidth: 200 }}>
                  <InputLabel>Telegram Library</InputLabel>
                  <Select
                    value={config.telegram.lib}
                    label="Telegram Library"
                    onChange={(e) =>
                      updateConfig(
                        "telegram.lib",
                        e.target.value as "pyrogram" | "telethon"
                      )
                    }
                  >
                    <MenuItem value="pyrogram">Pyrogram</MenuItem>
                    <MenuItem value="telethon">Telethon</MenuItem>
                  </Select>
                </FormControl>
              </FieldRow>

              <Box>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Private File Channels & Metadata
                </Typography>
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mb: 2 }}
                >
                  Configure one or more private channels to store files. Each
                  channel needs both a channel ID and metadata configuration to
                  maintain the directory structure.
                </Typography>
                {config.telegram.channels.map((channel, index) => (
                  <ChannelField
                    key={index}
                    index={index}
                    channel={channel}
                    onUpdate={(field, value) =>
                      updateChannel(index, field, value)
                    }
                    onUpdateGitHubRepo={(field, value) =>
                      updateChannelGitHubRepo(index, field, value)
                    }
                    onDelete={
                      config.telegram.channels.length > 1
                        ? () => removeChannel(index)
                        : undefined
                    }
                    canDelete={config.telegram.channels.length > 1}
                    nameErrors={getChannelNameErrors(index, channel.name)}
                    redundancyEnabled={redundancy.enabled}
                    mirrorErrors={getMirrorErrors(index)}
                    onAddMirror={() => addMirror(index)}
                    onRemoveMirror={(mirrorIndex) =>
                      removeMirror(index, mirrorIndex)
                    }
                    onUpdateMirror={(mirrorIndex, value) =>
                      updateMirror(index, mirrorIndex, value)
                    }
                  />
                ))}
                <Button
                  startIcon={<Add />}
                  onClick={addChannel}
                  variant="outlined"
                  size="small"
                  sx={{ mt: 1 }}
                >
                  Add Another Channel
                </Button>
              </Box>

              <FormControlLabel
                label="Use user account to upload files (No benefit unless you are a premium user)"
                control={
                  <Checkbox
                    checked={withUserAccountUpload}
                    onChange={(e) => {
                      setWithUserAccountUpload(e.target.checked);
                    }}
                  />
                }
              />
              <FormControlLabel
                label="Use user account to download files (No known benefit)"
                control={
                  <Checkbox
                    checked={withUserAccountDownload}
                    onChange={(e) => {
                      setWithUserAccountDownload(e.target.checked);
                    }}
                  />
                }
              />

              <Box>
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    gap: 2,
                    mt: 2,
                    mb: 2,
                  }}
                >
                  <Typography variant="h6">Bot Tokens</Typography>
                  <Button
                    variant="outlined"
                    size="small"
                    component="a"
                    href="https://t.me/botfather"
                    target="_blank"
                    rel="noopener noreferrer"
                    sx={{ textTransform: "none" }}
                  >
                    @BotFather
                  </Button>
                </Box>
                {config.telegram.bot.tokens.map((token, index) => (
                  <BotTokenField
                    key={index}
                    index={index}
                    value={token}
                    onChange={(value) => updateBotToken(index, value)}
                    onDelete={
                      index > 0 ? () => removeBotToken(index) : undefined
                    }
                  />
                ))}
                <Button
                  startIcon={<Add />}
                  onClick={addBotToken}
                  variant="outlined"
                  size="small"
                  sx={{ mt: 1 }}
                >
                  Add Another Bot Token
                </Button>
              </Box>
            </FormSection>

            <FormSection title="TGFS">
              <Box>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Users
                </Typography>
                {config.tgfs.users.map((user, index) => (
                  <UserField
                    key={index}
                    username={user.username}
                    password={user.password}
                    onUsernameChange={(username) =>
                      updateUser(index, "username", username)
                    }
                    onPasswordChange={(password) =>
                      updateUser(index, "password", password)
                    }
                    onDelete={index > 0 ? () => removeUser(index) : undefined}
                    canDelete={index > 0}
                  />
                ))}
                <Button
                  startIcon={<Add />}
                  onClick={addUser}
                  variant="outlined"
                  size="small"
                  sx={{ mt: 1, width: "fit-content" }}
                >
                  Add Another User
                </Button>
              </Box>
              <Typography variant="h6" sx={{ mt: 2, mb: 1 }}>
                JWT
              </Typography>
              <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
                <ConfigTextField
                  label="JWT Secret"
                  value={config.tgfs.jwt.secret}
                  onChange={(e) =>
                    updateConfig("tgfs.jwt.secret", e.target.value)
                  }
                  sx={{ flex: 1 }}
                />
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<Refresh />}
                  onClick={regenerateJwtSecret}
                  sx={{ minWidth: "120px" }}
                >
                  Regenerate
                </Button>
              </Box>
              <Typography variant="h6" sx={{ mt: 2, mb: 1 }}>
                Server
              </Typography>
              <FieldRow>
                <ConfigTextField
                  label="Host"
                  value={config.tgfs.server.host}
                  onChange={(e) =>
                    updateConfig("tgfs.server.host", e.target.value)
                  }
                  width={200}
                />
                <ConfigTextField
                  label="Port"
                  type="number"
                  value={config.tgfs.server.port}
                  onChange={(e) =>
                    updateConfig("tgfs.server.port", parseInt(e.target.value))
                  }
                  width={120}
                />
              </FieldRow>
              <Typography variant="body2" color="text.secondary">
                WebDAV server will be at{" "}
                <code>
                  http://{config.tgfs.server.host}:{config.tgfs.server.port}
                  /webdav
                </code>
              </Typography>
              <Typography variant="body2" color="text.secondary">
                TGFS server will be at{" "}
                <code>
                  http://{config.tgfs.server.host}:{config.tgfs.server.port}
                </code>{" "}
                {"("}Used in the{" "}
                <a href="https://xyvran.github.io/tgfs/telegram-mini-app/">
                  <u>Telegram Mini App</u>
                </a>
                {")"}.
              </Typography>
            </FormSection>

            <FormSection title="SFTP (Optional)">
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Serves the same file tree over SFTP, next to WebDAV, using the
                same users and the same readonly flags. SSH cannot share the
                HTTP port, so it needs a port of its own.
              </Typography>
              <FormControlLabel
                label="Enable the SFTP interface"
                control={
                  <Checkbox
                    checked={config.tgfs.sftp.enabled}
                    onChange={(e) =>
                      updateConfig("tgfs.sftp", {
                        ...config.tgfs.sftp,
                        enabled: e.target.checked,
                      })
                    }
                  />
                }
              />
              {config.tgfs.sftp.enabled && (
                <>
                  <FieldRow>
                    <ConfigTextField
                      label="Host"
                      value={config.tgfs.sftp.host}
                      onChange={(e) =>
                        updateConfig("tgfs.sftp", {
                          ...config.tgfs.sftp,
                          host: e.target.value,
                        })
                      }
                      width={200}
                    />
                    <ConfigTextField
                      label="Port"
                      type="number"
                      value={config.tgfs.sftp.port}
                      onChange={(e) =>
                        updateConfig("tgfs.sftp", {
                          ...config.tgfs.sftp,
                          port: parseInt(e.target.value),
                        })
                      }
                      width={120}
                    />
                  </FieldRow>
                  <Typography variant="body2" color="text.secondary">
                    Connect with{" "}
                    <code>
                      sftp -P {config.tgfs.sftp.port} &lt;user&gt;@
                      {config.tgfs.sftp.host}
                    </code>
                  </Typography>
                  <FieldRow>
                    <ConfigTextField
                      label="Host Key File"
                      value={config.tgfs.sftp.host_key_file}
                      onChange={(e) =>
                        updateConfig("tgfs.sftp", {
                          ...config.tgfs.sftp,
                          host_key_file: e.target.value,
                        })
                      }
                      width={280}
                    />
                    <ConfigTextField
                      label="Upload Buffer (MB)"
                      type="number"
                      value={config.tgfs.sftp.upload_buffer_size_mb}
                      onChange={(e) =>
                        updateConfig("tgfs.sftp", {
                          ...config.tgfs.sftp,
                          upload_buffer_size_mb: parseInt(e.target.value),
                        })
                      }
                      width={180}
                    />
                  </FieldRow>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mb: 1 }}
                  >
                    The host key is generated on first start and must be backed
                    up — a new one on every restart makes clients refuse to
                    connect. SFTP never announces an upload&apos;s size, so a
                    file is buffered in memory up to the size above and spills
                    to disk beyond it.
                  </Typography>
                  <ConfigTextField
                    label="Authorized Keys Directory (optional)"
                    value={config.tgfs.sftp.authorized_keys_dir}
                    onChange={(e) =>
                      updateConfig("tgfs.sftp", {
                        ...config.tgfs.sftp,
                        authorized_keys_dir: e.target.value,
                      })
                    }
                    width={360}
                  />
                  <Typography variant="body2" color="text.secondary">
                    Leave empty for password login only. Otherwise put one file
                    per user in that directory, named after the username, in
                    the usual <code>authorized_keys</code> format. The user
                    still has to be listed above so the readonly flag applies.
                  </Typography>
                </>
              )}
            </FormSection>

            <FormSection title="Redundancy (Optional)">
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                RAID-1-style mirroring: every file uploaded to a channel is
                also copied to its mirror channel(s) via server-side message
                forwarding, so your data survives a channel getting banned
                or deleted. Configure the mirror channel IDs per channel
                above once enabled. Enabling this later is fine — the
                backfill task (Manager API:{" "}
                <code>POST /redundancy/backfill/&lt;channel-name&gt;</code>)
                mirrors all pre-existing files without re-uploading them.
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Tip: with redundancy enabled, the GitHub Repository metadata
                type is recommended — the directory structure then survives
                even the loss of all channels.
              </Typography>
              <FormControlLabel
                label="Enable channel redundancy"
                control={
                  <Checkbox
                    checked={redundancy.enabled}
                    onChange={(e) =>
                      setRedundancy({
                        ...redundancy,
                        enabled: e.target.checked,
                      })
                    }
                  />
                }
              />
              {redundancy.enabled && (
                <>
                  <FieldRow>
                    <FormControl size="small" sx={{ minWidth: 220 }}>
                      <InputLabel>Mirroring Mode</InputLabel>
                      <Select
                        value={redundancy.mode}
                        label="Mirroring Mode"
                        onChange={(e) =>
                          setRedundancy({
                            ...redundancy,
                            mode: e.target.value as "forward" | "reupload",
                          })
                        }
                      >
                        <MenuItem value="forward">
                          Forward (server-side, recommended)
                        </MenuItem>
                        <MenuItem value="reupload">
                          Re-upload (for restricted channels)
                        </MenuItem>
                      </Select>
                    </FormControl>
                  </FieldRow>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mb: 1 }}
                  >
                    &quot;Forward&quot; copies files on Telegram&apos;s
                    servers without using your bandwidth, but requires the
                    primary channel to allow forwarding (&quot;Restrict
                    saving content&quot; must be off). &quot;Re-upload&quot;
                    always works but downloads and uploads every byte again.
                  </Typography>
                  <FormControlLabel
                    label="Strict mode (fail uploads when mirroring fails; default is log-and-continue)"
                    control={
                      <Checkbox
                        checked={redundancy.strict}
                        onChange={(e) =>
                          setRedundancy({
                            ...redundancy,
                            strict: e.target.checked,
                          })
                        }
                      />
                    }
                  />
                </>
              )}
            </FormSection>

            <FormSection title="Encryption (Optional)">
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                At-rest encryption with AES-256-GCM. When enabled, every file
                is encrypted client-side before being uploaded; the Telegram
                channel only ever sees ciphertext plus a public per-file salt.
              </Typography>
              <EncryptionField
                config={config.tgfs.encryption}
                onUpdate={(field, value) =>
                  updateConfig("tgfs.encryption", {
                    ...config.tgfs.encryption,
                    [field]: value,
                  })
                }
              />
            </FormSection>

            <FormSection title="Transfer Performance (Optional)">
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                How file bytes are moved to and from Telegram. Every setting
                has a default that matches the behaviour you get without this
                block, so leave it off unless you want to tune something.
              </Typography>
              <FormControlLabel
                label="Tune transfer settings"
                control={
                  <Checkbox
                    checked={config.tgfs.transfer.enabled}
                    onChange={(e) =>
                      updateConfig("tgfs.transfer", {
                        ...config.tgfs.transfer,
                        enabled: e.target.checked,
                      })
                    }
                  />
                }
              />
              {config.tgfs.transfer.enabled && (
                <>
                  <Typography variant="subtitle2" sx={{ mt: 1 }}>
                    Downloads
                  </Typography>
                  <FieldRow>
                    <ConfigTextField
                      label="Piece Size (KB)"
                      type="number"
                      value={config.tgfs.transfer.download_piece_size_kb}
                      onChange={(e) =>
                        updateConfig("tgfs.transfer", {
                          ...config.tgfs.transfer,
                          download_piece_size_kb: parseInt(e.target.value),
                        })
                      }
                      width={170}
                    />
                    <ConfigTextField
                      label="Pieces In Flight"
                      type="number"
                      value={config.tgfs.transfer.download_pieces_in_flight}
                      onChange={(e) =>
                        updateConfig("tgfs.transfer", {
                          ...config.tgfs.transfer,
                          download_pieces_in_flight: parseInt(e.target.value),
                        })
                      }
                      width={170}
                    />
                    <ConfigTextField
                      label="Split Above (MB)"
                      type="number"
                      value={
                        config.tgfs.transfer.parallel_download_threshold_mb
                      }
                      onChange={(e) =>
                        updateConfig("tgfs.transfer", {
                          ...config.tgfs.transfer,
                          parallel_download_threshold_mb: parseInt(
                            e.target.value
                          ),
                        })
                      }
                      width={170}
                    />
                  </FieldRow>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mb: 1 }}
                  >
                    A download is cut into pieces and several are fetched at
                    once. Bytes have to be handed out in order, so a piece
                    that arrives early waits its turn:{" "}
                    <strong>
                      peak buffering is{" "}
                      {(
                        (config.tgfs.transfer.download_piece_size_kb *
                          config.tgfs.transfer.download_pieces_in_flight) /
                        1024
                      ).toFixed(0)}{" "}
                      MiB per download
                    </strong>
                    , for every reader at the same time.
                  </Typography>

                  <Typography variant="subtitle2" sx={{ mt: 1 }}>
                    Connections
                  </Typography>
                  <ConfigTextField
                    label="Connections Per Bot"
                    type="number"
                    value={config.tgfs.transfer.connection_pool_size}
                    onChange={(e) =>
                      updateConfig("tgfs.transfer", {
                        ...config.tgfs.transfer,
                        connection_pool_size: parseInt(e.target.value),
                      })
                    }
                    width={200}
                  />
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mb: 1 }}
                  >
                    Pieces are handed to the bot tokens above in turn, so each
                    extra token is another connection a download can use. With
                    a single token, raise this instead: one connection sends
                    its requests one after another, so extra connections are
                    what let one bot overlap transfers.
                  </Typography>

                  <Typography variant="subtitle2" sx={{ mt: 1 }}>
                    Uploads
                  </Typography>
                  <FieldRow>
                    <ConfigTextField
                      label="Workers (Small Files)"
                      type="number"
                      value={config.tgfs.transfer.upload_workers_small}
                      onChange={(e) =>
                        updateConfig("tgfs.transfer", {
                          ...config.tgfs.transfer,
                          upload_workers_small: parseInt(e.target.value),
                        })
                      }
                      width={190}
                    />
                    <ConfigTextField
                      label="Workers (Large Files)"
                      type="number"
                      value={config.tgfs.transfer.upload_workers_big}
                      onChange={(e) =>
                        updateConfig("tgfs.transfer", {
                          ...config.tgfs.transfer,
                          upload_workers_big: parseInt(e.target.value),
                        })
                      }
                      width={190}
                    />
                    <FormControl size="small" sx={{ minWidth: 150 }}>
                      <InputLabel>Part Size (KB)</InputLabel>
                      <Select
                        label="Part Size (KB)"
                        value={config.tgfs.transfer.upload_part_size_kb}
                        onChange={(e) =>
                          updateConfig("tgfs.transfer", {
                            ...config.tgfs.transfer,
                            upload_part_size_kb: Number(e.target.value),
                          })
                        }
                      >
                        {[64, 128, 256, 512].map((size) => (
                          <MenuItem key={size} value={size}>
                            {size}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </FieldRow>
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ mb: 1 }}
                  >
                    Telegram only accepts part sizes that divide 512 KB and
                    caps them there, which is why this is a fixed list. More
                    workers means more requests per second; if uploads start
                    logging flood waits, lower this and the connection count
                    before raising anything else.
                  </Typography>

                  <Typography variant="subtitle2" sx={{ mt: 1 }}>
                    Chunk Cache
                  </Typography>
                  <FieldRow>
                    <ConfigTextField
                      label="Cache Budget (MB)"
                      type="number"
                      value={config.tgfs.transfer.chunk_cache_mb}
                      onChange={(e) =>
                        updateConfig("tgfs.transfer", {
                          ...config.tgfs.transfer,
                          chunk_cache_mb: parseInt(e.target.value),
                        })
                      }
                      width={170}
                    />
                    <ConfigTextField
                      label="Block Size (KB)"
                      type="number"
                      value={config.tgfs.transfer.chunk_cache_block_kb}
                      onChange={(e) =>
                        updateConfig("tgfs.transfer", {
                          ...config.tgfs.transfer,
                          chunk_cache_block_kb: parseInt(e.target.value),
                        })
                      }
                      width={170}
                    />
                    <ConfigTextField
                      label="Read-Ahead Blocks"
                      type="number"
                      value={config.tgfs.transfer.chunk_cache_readahead}
                      onChange={(e) =>
                        updateConfig("tgfs.transfer", {
                          ...config.tgfs.transfer,
                          chunk_cache_readahead: parseInt(e.target.value),
                        })
                      }
                      width={170}
                    />
                  </FieldRow>
                  <Typography variant="body2" color="text.secondary">
                    Keeps downloaded blocks in memory, so readers that revisit
                    bytes stop fetching them twice: seeking in a video, or an
                    SFTP client walking a file in small reads. A budget of 0
                    disables it. A read of a few kilobytes pulls a whole
                    block, so a larger block serves more of the reads that
                    follow and wastes more on readers that jump around.
                  </Typography>
                </>
              )}
            </FormSection>
          </Paper>
        </Box>

        <Box sx={{ width: { xs: "100%", md: "400px" }, flexShrink: 0 }}>
          <Paper sx={{ p: 3, position: "sticky", top: 24 }}>
            <Typography variant="h6" gutterBottom>
              Generated Configuration
            </Typography>

            <Box sx={{ mb: 2 }}>
              <Button
                fullWidth
                variant="contained"
                startIcon={<Download />}
                onClick={downloadConfig}
                sx={{ mb: 1 }}
              >
                Download config.yaml
              </Button>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<ContentCopy />}
                onClick={copyToClipboard}
              >
                Copy to Clipboard
              </Button>
            </Box>

            <Card variant="outlined">
              <CardContent sx={{ p: 0 }}>
                <SyntaxHighlighter
                  language="yaml"
                  style={vscDarkPlus}
                  customStyle={{
                    fontSize: "0.75rem",
                    margin: 0,
                  }}
                >
                  {generateYaml()}
                </SyntaxHighlighter>
              </CardContent>
            </Card>
          </Paper>
        </Box>
      </Box>
    </Container>
  );
}
