import { ContentCopy } from "@mui/icons-material";
import {
  Box,
  Button,
  Checkbox,
  FormControlLabel,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import { useEffect, useState } from "react";
import { ConfigTextField } from "./ConfigTextField";

type PathStyle = "unix" | "windows";

interface DockerRunPanelProps {
  // Image without a tag, e.g. "xyvran/tgdcfs".
  image: string;
  // Container name and the directory the image reads its config from.
  containerName: string;
  dataDir: string;
  // Directory name suggested on the host, e.g. ".tgdcfs".
  hostDirName: string;
  // Ports to publish, container port = host port.
  ports: number[];
  // Environment variables passed through from the shell (-e NAME).
  envVars: string[];
}

const defaultHostPath = (style: PathStyle, dirName: string): string =>
  style === "windows"
    ? `C:\\Users\\user\\${dirName}`
    : `/home/user/${dirName}`;

// The docker run command for the config the form describes: one -p per
// published port, the data directory mounted where the image expects it
// and the passphrase variable passed through when encryption reads one.
export function DockerRunPanel({
  image,
  containerName,
  dataDir,
  hostDirName,
  ports,
  envVars,
}: DockerRunPanelProps) {
  const [pathStyle, setPathStyle] = useState<PathStyle>("unix");
  const [hostPath, setHostPath] = useState(defaultHostPath("unix", hostDirName));
  const [detached, setDetached] = useState(false);
  const [copied, setCopied] = useState(false);

  // Pick the path style of the visitor's machine once, on the client.
  useEffect(() => {
    if (window.navigator.userAgent.includes("Windows")) {
      setPathStyle("windows");
      setHostPath(defaultHostPath("windows", hostDirName));
    }
  }, [hostDirName]);

  const changeStyle = (style: PathStyle | null) => {
    if (!style) return;
    setPathStyle(style);
    setHostPath(defaultHostPath(style, hostDirName));
  };

  const uniquePorts = Array.from(new Set(ports.filter((p) => p > 0)));
  const args = [
    "docker run",
    detached ? "-d --restart unless-stopped" : "-it",
    "--pull=always",
    `--name ${containerName}`,
    ...uniquePorts.map((p) => `-p ${p}:${p}`),
    ...envVars.map((name) => `-e ${name}`),
    `-v "${hostPath}:${dataDir}"`,
    `${image}:latest`,
  ];
  const command = args.join(" ");

  const copy = () => {
    navigator.clipboard.writeText(command).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Docker Run Command
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Put the downloaded config.yaml into the directory below; the
        sessions, the salt and the cache are written next to it.
      </Typography>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
        <Typography variant="body2" color="text.secondary">
          Path Style:
        </Typography>
        <ToggleButtonGroup
          value={pathStyle}
          exclusive
          onChange={(_, style) => changeStyle(style)}
          size="small"
        >
          <ToggleButton value="unix">Unix</ToggleButton>
          <ToggleButton value="windows">Windows</ToggleButton>
        </ToggleButtonGroup>
      </Box>
      <ConfigTextField
        label="Directory of config.yaml"
        value={hostPath}
        onChange={(e) => setHostPath(e.target.value)}
        width="100%"
        sx={{ mb: 1 }}
      />
      <FormControlLabel
        label="Run in the background and restart with Docker"
        control={
          <Checkbox
            checked={detached}
            onChange={(e) => setDetached(e.target.checked)}
            size="small"
          />
        }
        sx={{ mb: 1 }}
      />
      <Box
        sx={{
          bgcolor: "#1e1e1e",
          color: "grey.100",
          p: 2,
          borderRadius: 1,
        }}
      >
        <Typography
          variant="body2"
          component="code"
          sx={{
            display: "block",
            wordBreak: "break-all",
            fontFamily: "monospace",
            fontSize: "0.75rem",
          }}
        >
          {command}
        </Typography>
        <Button
          size="small"
          startIcon={<ContentCopy />}
          onClick={copy}
          sx={{ mt: 1, color: "grey.400" }}
        >
          {copied ? "Copied" : "Copy Command"}
        </Button>
      </Box>
      {envVars.length > 0 && (
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          Export {envVars.map((name, i) => (
            <span key={name}>
              {i > 0 ? " and " : ""}
              <code>{name}</code>
            </span>
          ))}{" "}
          in the shell first; Docker passes the value through without it
          appearing in the command.
        </Typography>
      )}
    </Box>
  );
}
