import { Visibility, VisibilityOff } from "@mui/icons-material";
import {
  Alert,
  AlertTitle,
  Box,
  FormControl,
  FormControlLabel,
  IconButton,
  InputAdornment,
  InputLabel,
  MenuItem,
  Select,
  Switch,
  Typography,
} from "@mui/material";
import { useState } from "react";
import { ConfigTextField } from "./ConfigTextField";

export type PassphraseSource = "passphrase" | "passphrase_env" | "passphrase_file";

export interface EncryptionConfig {
  enabled: boolean;
  encrypt_names: boolean;
  passphrase_source: PassphraseSource;
  passphrase: string;
  passphrase_env: string;
  passphrase_file: string;
  master_salt_file: string;
  chunk_size: number;
}

interface EncryptionFieldProps {
  config: EncryptionConfig;
  onUpdate: <K extends keyof EncryptionConfig>(
    field: K,
    value: EncryptionConfig[K]
  ) => void;
}

export function EncryptionField({ config, onUpdate }: EncryptionFieldProps) {
  const [showPassphrase, setShowPassphrase] = useState(false);

  return (
    <Box>
      <FormControlLabel
        control={
          <Switch
            checked={config.enabled}
            onChange={(e) => onUpdate("enabled", e.target.checked)}
          />
        }
        label={
          <Box>
            <Typography variant="body1">Enable at-rest encryption</Typography>
            <Typography variant="caption" color="text.secondary">
              Files are encrypted client-side with AES-256-GCM before upload.
              Telegram never sees plaintext.
            </Typography>
          </Box>
        }
        sx={{ alignItems: "flex-start", mb: 2 }}
      />

      {config.enabled && (
        <Box sx={{ pl: 2, borderLeft: 2, borderColor: "divider" }}>
          <Alert severity="warning" sx={{ mb: 2 }}>
            <AlertTitle>Back up your salt and passphrase</AlertTitle>
            Losing either makes existing encrypted files unrecoverable. There
            is no recovery path -- by design, only someone holding the
            passphrase plus the master salt can decrypt your files.
          </Alert>

          <Typography variant="subtitle1" sx={{ mb: 1, fontWeight: 600 }}>
            Passphrase Source
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Pick exactly one source. The passphrase is fed into Argon2id once at
            startup to derive the 256-bit master key.
          </Typography>

          <FormControl size="small" fullWidth sx={{ mb: 2 }}>
            <InputLabel>Source Type</InputLabel>
            <Select
              value={config.passphrase_source}
              label="Source Type"
              onChange={(e) =>
                onUpdate(
                  "passphrase_source",
                  e.target.value as PassphraseSource
                )
              }
            >
              <MenuItem value="passphrase_env">
                Environment Variable (recommended for containers)
              </MenuItem>
              <MenuItem value="passphrase_file">
                File (recommended for systemd / LoadCredential=)
              </MenuItem>
              <MenuItem value="passphrase">
                Inline string (NOT recommended outside development)
              </MenuItem>
            </Select>
          </FormControl>

          {config.passphrase_source === "passphrase" && (
            <Box sx={{ mb: 2 }}>
              <ConfigTextField
                label="Passphrase"
                value={config.passphrase}
                onChange={(e) => onUpdate("passphrase", e.target.value)}
                type={showPassphrase ? "text" : "password"}
                fullWidth
                required
                helperText="Stored in clear text inside config.yaml. Use only for testing."
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        size="small"
                        onClick={() => setShowPassphrase(!showPassphrase)}
                        edge="end"
                      >
                        {showPassphrase ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
            </Box>
          )}

          {config.passphrase_source === "passphrase_env" && (
            <Box sx={{ mb: 2 }}>
              <ConfigTextField
                label="Environment Variable Name"
                value={config.passphrase_env}
                onChange={(e) => onUpdate("passphrase_env", e.target.value)}
                fullWidth
                required
                helperText='TGFS reads this env var at startup. e.g. "TGFS_MASTER_PASSPHRASE"'
              />
            </Box>
          )}

          {config.passphrase_source === "passphrase_file" && (
            <Box sx={{ mb: 2 }}>
              <ConfigTextField
                label="Passphrase File Path"
                value={config.passphrase_file}
                onChange={(e) => onUpdate("passphrase_file", e.target.value)}
                fullWidth
                required
                helperText="Path is relative to TGFS_DATA_DIR (~/.tgfs by default). Trailing newline is stripped."
              />
            </Box>
          )}

          <Typography variant="subtitle1" sx={{ mt: 3, mb: 1, fontWeight: 600 }}>
            Master Salt
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            16 random bytes generated on first run. Not secret, but
            <b> losing it means the master key cannot be re-derived</b>. Back
            this file up alongside your metadata.
          </Typography>
          <ConfigTextField
            label="Master Salt File"
            value={config.master_salt_file}
            onChange={(e) => onUpdate("master_salt_file", e.target.value)}
            fullWidth
            sx={{ mb: 3 }}
            helperText="Path relative to TGFS_DATA_DIR. Default: master.salt"
          />

          <Typography variant="subtitle1" sx={{ mb: 1, fontWeight: 600 }}>
            Chunk Size
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Plaintext bytes per AES-GCM chunk. Larger chunks reduce auth-tag
            overhead; smaller chunks improve random-access granularity. Each
            chunk costs 28 bytes (12-byte nonce + 16-byte tag).
          </Typography>
          <ConfigTextField
            label="Chunk Size (bytes)"
            type="number"
            value={config.chunk_size}
            onChange={(e) =>
              onUpdate("chunk_size", parseInt(e.target.value) || 65536)
            }
            width={220}
            helperText="Default: 65536 (64 KiB). Max: 16 MiB."
          />

          <Typography variant="subtitle1" sx={{ mt: 3, mb: 1, fontWeight: 600 }}>
            Filename Encryption (Optional)
          </Typography>
          <FormControlLabel
            control={
              <Switch
                checked={config.encrypt_names}
                onChange={(e) => onUpdate("encrypt_names", e.target.checked)}
              />
            }
            label={
              <Box>
                <Typography variant="body1">
                  Encrypt Telegram-visible document names
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Replaces every uploaded document name -- including the
                  pinned metadata blob -- with an AES-GCM ciphertext token
                  (<code>TGFS1_&lt;base64url&gt;</code>). A passive observer of
                  the channel cannot read file or directory names from the
                  document metadata. Plaintext names remain inside the
                  (also encrypted) metadata.json, so WebDAV and the manager
                  UI are unaffected.
                </Typography>
              </Box>
            }
            sx={{ alignItems: "flex-start", mb: 1 }}
          />
          {config.encrypt_names && (
            <Alert severity="info" sx={{ mt: 1, mb: 2 }}>
              Only <b>new uploads</b> are affected. Files that were already in
              the channel keep their original Telegram document name -- enabling
              this later does not rewrite existing parts.
            </Alert>
          )}

          <Alert severity="info" sx={{ mt: 3 }}>
            <AlertTitle>How it works</AlertTitle>
            <Box component="ul" sx={{ pl: 2, m: 0 }}>
              <li>
                <b>Master key:</b> Argon2id(passphrase, master_salt) -- run once
                at startup (t=3, m=64 MiB, p=4).
              </li>
              <li>
                <b>Per-file key:</b> HKDF-SHA256(master_key, file_salt) -- a
                fresh 32-byte salt per file means leaking one file&apos;s key
                does not affect other files.
              </li>
              <li>
                <b>Cipher:</b> AES-256-GCM in independent chunks with
                deterministic nonces (file_salt[:4] || chunk_index).
              </li>
              <li>
                <b>Self-describing:</b> a 60-byte header (magic, version,
                algorithm, chunk size, file salt, MAC) is prepended to each
                file so it can be decrypted even if the TGFS metadata is lost.
              </li>
              <li>
                <b>Legacy files:</b> plaintext files uploaded before encryption
                was enabled keep working -- they are detected by the missing
                magic and read transparently.
              </li>
            </Box>
          </Alert>
        </Box>
      )}
    </Box>
  );
}
