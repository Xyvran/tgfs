import { UploadFile } from "@mui/icons-material";
import { Button } from "@mui/material";
import { ChangeEvent, useRef } from "react";

interface LoadConfigButtonProps {
  // Called with the text of the picked file; the caller parses it.
  onLoad: (text: string) => void;
  onError: (message: string) => void;
  fullWidth?: boolean;
}

// Opens a file picker for a config.yaml and hands its text back. The
// file is read in the browser only; nothing is uploaded anywhere.
export function LoadConfigButton({
  onLoad,
  onError,
  fullWidth = false,
}: LoadConfigButtonProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  const onChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    // Reset so picking the same file again fires the change event.
    event.target.value = "";
    if (!file) return;
    file
      .text()
      .then(onLoad)
      .catch((err: unknown) =>
        onError(err instanceof Error ? err.message : String(err))
      );
  };

  return (
    <>
      <input
        type="file"
        ref={inputRef}
        style={{ display: "none" }}
        accept=".yaml,.yml,application/x-yaml,text/yaml"
        onChange={onChange}
      />
      <Button
        fullWidth={fullWidth}
        variant="outlined"
        startIcon={<UploadFile />}
        onClick={() => inputRef.current?.click()}
      >
        Load Existing config.yaml
      </Button>
    </>
  );
}
