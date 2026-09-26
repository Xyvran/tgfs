import { Delete } from "@mui/icons-material";
import { Box, Checkbox, FormControlLabel, IconButton } from "@mui/material";
import { ConfigTextField } from "./ConfigTextField";

interface UserFieldProps {
  username: string;
  password: string;
  readonly: boolean;
  onUsernameChange: (username: string) => void;
  onPasswordChange: (password: string) => void;
  onReadonlyChange: (readonly: boolean) => void;
  onDelete?: () => void;
  canDelete: boolean;
}

export function UserField({
  username,
  password,
  readonly,
  onUsernameChange,
  onPasswordChange,
  onReadonlyChange,
  onDelete,
  canDelete,
}: UserFieldProps) {
  return (
    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
      <ConfigTextField
        label="Username"
        value={username}
        onChange={(e) => onUsernameChange(e.target.value)}
        style={{ flex: 1 }}
        required
      />
      <ConfigTextField
        label="Password"
        value={password}
        onChange={(e) => onPasswordChange(e.target.value)}
        style={{ flex: 1 }}
        required
      />
      <FormControlLabel
        label="Read-only"
        sx={{ mt: 0.25, whiteSpace: "nowrap" }}
        control={
          <Checkbox
            checked={readonly}
            onChange={(e) => onReadonlyChange(e.target.checked)}
            size="small"
          />
        }
      />
      {canDelete && onDelete && (
        <IconButton
          color="error"
          onClick={onDelete}
          sx={{ mt: 0.5 }}
          size="small"
        >
          <Delete />
        </IconButton>
      )}
    </Box>
  );
}
