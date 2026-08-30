import React, { useRef, useState } from 'react';
import { UploadCloud, FileCode2, AlertCircle, CheckCircle2 } from 'lucide-react';
import { formatBytes } from '../../utils/formatters';

interface PcapUploadZoneProps {
  onFileSelected: (file: File) => void;
  isAnalyzing: boolean;
}

const MAX_SIZE_BYTES = 50 * 1024 * 1024; // 50MB

export const PcapUploadZone: React.FC<PcapUploadZoneProps> = ({
  onFileSelected,
  isAnalyzing,
}) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateAndSelect = (file: File) => {
    setValidationError(null);

    const ext = file.name.toLowerCase();
    const isValidExt = ext.endsWith('.pcap') || ext.endsWith('.pcapng') || ext.endsWith('.cap');
    if (!isValidExt) {
      setValidationError('Please select a valid capture file (.pcap or .pcapng).');
      return;
    }

    if (file.size > MAX_SIZE_BYTES) {
      setValidationError(`File size (${formatBytes(file.size)}) exceeds the maximum 50 MB limit.`);
      return;
    }

    if (file.size === 0) {
      setValidationError('Selected file is empty (0 bytes).');
      return;
    }

    setSelectedFile(file);
    onFileSelected(file);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (isAnalyzing) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSelect(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (!isAnalyzing) {
      setIsDragOver(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSelect(e.target.files[0]);
    }
  };

  return (
    <div className="space-y-3">
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => !isAnalyzing && fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-2xl p-8 text-center transition-all cursor-pointer ${
          isDragOver
            ? 'border-blue-500 bg-blue-950/30 ring-4 ring-blue-500/20'
            : selectedFile
            ? 'border-emerald-600/50 bg-slate-900/60'
            : 'border-slate-800 hover:border-slate-700 bg-slate-900/40 hover:bg-slate-900/60'
        } ${isAnalyzing ? 'opacity-60 cursor-not-allowed pointer-events-none' : ''}`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={handleFileChange}
          className="hidden"
          disabled={isAnalyzing}
        />

        <div className="flex flex-col items-center justify-center space-y-3">
          <div
            className={`w-14 h-14 rounded-2xl flex items-center justify-center border transition-all ${
              selectedFile
                ? 'bg-emerald-950/60 border-emerald-600/40 text-emerald-400'
                : 'bg-blue-950/40 border-blue-600/30 text-blue-400'
            }`}
          >
            {selectedFile ? (
              <FileCode2 className="w-7 h-7" />
            ) : (
              <UploadCloud className="w-7 h-7" />
            )}
          </div>

          <div>
            {selectedFile ? (
              <div className="space-y-1">
                <div className="flex items-center justify-center gap-2 text-sm font-semibold text-slate-200">
                  <span>{selectedFile.name}</span>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 inline" />
                </div>
                <p className="text-xs text-slate-400">
                  {formatBytes(selectedFile.size)} • Ready for automated ML analysis
                </p>
              </div>
            ) : (
              <div className="space-y-1">
                <p className="text-sm font-medium text-slate-200">
                  <span className="text-blue-400 font-semibold">Click to upload</span> or drag and drop PCAP capture
                </p>
                <p className="text-xs text-slate-400">
                  Supports standard <code className="text-slate-300">.pcap</code> and <code className="text-slate-300">.pcapng</code> formats (up to 50 MB, 10,000 flows max)
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {validationError && (
        <div className="flex items-center gap-2 p-3 bg-red-950/70 border border-red-800/50 rounded-xl text-red-300 text-xs">
          <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{validationError}</span>
        </div>
      )}
    </div>
  );
};
