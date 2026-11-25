"use client";

import React, { useMemo, useState } from "react";
import { validateGroth16 } from "./validator";
import { generateCargoToml, generateCliCommands, generateLibRs, proofBytesHex } from "./codegen";
import { SAMPLES } from "./samples";

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

const area = "w-full h-40 font-mono text-xs p-3 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900";

function Output({ title, text, file }: { title: string; text: string; file?: string }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-sm">{title}</h3>
        <div className="flex gap-2 text-xs">
          <button className="underline" onClick={() => navigator.clipboard?.writeText(text)}>Copy</button>
          {file && <button className="underline" onClick={() => download(file, text)}>Download</button>}
        </div>
      </div>
      <pre className="overflow-x-auto max-h-80 text-xs p-3 rounded-lg border border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-900">{text}</pre>
    </div>
  );
}

export function ZkPlayground() {
  const [vk, setVk] = useState("");
  const [proof, setProof] = useState("");
  const [pub, setPub] = useState("");

  const result = useMemo(() => (vk || proof || pub ? validateGroth16(vk, proof, pub) : null), [vk, proof, pub]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-2 items-center">
        <span className="text-sm font-medium">Samples:</span>
        {SAMPLES.map((s) => (
          <button
            key={s.name}
            className="px-3 py-1 text-xs rounded-lg border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800"
            onClick={() => { setVk(s.vk); setProof(s.proof); setPub(s.publicInputs); }}
          >
            {s.name}
          </button>
        ))}
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        <label className="space-y-1 text-sm">verification_key.json
          <textarea className={area} value={vk} onChange={(e) => setVk(e.target.value)} spellCheck={false} />
        </label>
        <label className="space-y-1 text-sm">proof.json
          <textarea className={area} value={proof} onChange={(e) => setProof(e.target.value)} spellCheck={false} />
        </label>
        <label className="space-y-1 text-sm">public.json
          <textarea className={area} value={pub} onChange={(e) => setPub(e.target.value)} spellCheck={false} />
        </label>
      </div>

      {result && (
        <ul className="space-y-1 text-xs font-mono" aria-label="Validation results">
          {result.badges.map((b, i) => (
            <li key={i} className={b.ok ? "text-green-600 dark:text-green-400" : "text-red-600 dark:text-red-400"}>
              {b.ok ? "✓" : "✗"} {b.path} — {b.message}
            </li>
          ))}
        </ul>
      )}

      {result?.ok && result.vk && result.proof && result.publicInputs && (
        <div className="space-y-6">
          <Output title="lib.rs" file="lib.rs" text={generateLibRs(result.vk, result.publicInputs.length)} />
          <Output title="Cargo.toml" file="Cargo.toml" text={generateCargoToml()} />
          <Output title="proof_bytes (256 bytes, hex)" text={proofBytesHex(result.proof)} />
          <Output title="stellar CLI (Testnet)" text={generateCliCommands(result.proof, result.publicInputs)} />
        </div>
      )}
    </div>
  );
}
