"use client";
import React, { useState, useEffect } from 'react';
import { TransactionBuilder, Networks, Horizon, Contract, Address, rpc, nativeToScVal, xdr, SorobanDataBuilder, StrKey } from '@stellar/stellar-sdk';
import { decryptAmount, encryptAmount } from '../lib/decryption.mjs';

const config = {
  backendUrl: process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:3001',
  sorobanRpc: process.env.NEXT_PUBLIC_SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org',
  horizonRpc: process.env.NEXT_PUBLIC_HORIZON_RPC_URL || 'https://horizon-testnet.stellar.org',
  friendbotUrl: process.env.NEXT_PUBLIC_FRIENDBOT_URL || 'https://friendbot.stellar.org',
  networkPassphrase: process.env.NEXT_PUBLIC_NETWORK_PASSPHRASE || Networks.TESTNET,
  contractId: process.env.NEXT_PUBLIC_CONTRACT_ID || 'CCE7SJDDRQEXOGF7PNIY26LY63ZUXGBIYXZ3ZY3J4MGSJSXFXTUS5NTN',
  explorerTxUrl:
    process.env.NEXT_PUBLIC_EXPLORER_TX_URL ||
    'https://stellar.expert/explorer/testnet/tx/',
  explorerContractUrl:
    process.env.NEXT_PUBLIC_EXPLORER_CONTRACT_URL ||
    'https://stellar.expert/explorer/testnet/contract/',
  explorerDashboardUrl:
    process.env.NEXT_PUBLIC_EXPLORER_DASHBOARD_URL ||
    'https://lab.stellar.org/transaction/dashboard',
};

export default function Home() {
  const [address, setAddress] = useState<string | null>(null);
  const [balance, setBalance] = useState<string | null>(null);
  const [shieldedBalance, setShieldedBalance] = useState<number>(0);
  const [receiverAddress, setReceiverAddress] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [sendStep, setSendStep] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [isDecrypted, setIsDecrypted] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptedAmount, setDecryptedAmount] = useState<number | null>(null);
  const [isUnshielding, setIsUnshielding] = useState(false);
  const [isShielding, setIsShielding] = useState(false);
  const [shieldStep, setShieldStep] = useState("");
  const [realTransactions, setRealTransactions] = useState<any[]>([]);
  const [contractEvents, setContractEvents] = useState<any[]>([]);
  const [transactions, setTransactions] = useState<any[]>([]);

  const fetchRealTransactions = async (pubKey: string) => {
    try {
      const res = await fetch(`${config.horizonRpc}/accounts/${pubKey}/transactions?order=desc&limit=10`);
      const data = await res.json();
      setRealTransactions(data._embedded?.records || []);
    } catch(e) {
      console.error(e);
    }
  };

  const fetchContractEvents = async () => {
    try {
      const res = await fetch(`${config.backendUrl}/api/contract-events`);
      const data = await res.json();
      setContractEvents(data.events || []);
    } catch(e) {
      console.error('Failed to fetch contract events:', e);
    }
  };

  /**
   * Single function that syncs everything from the backend in one call.
   * The backend reads balance directly from the Soroban contract and
   * returns the latest transactions from MongoDB.
   */
  const syncWithBackend = async (pubKey: string) => {
    try {
      // Trigger a chain event sync on the backend first
      await fetch(`${config.backendUrl}/api/sync`).catch(() => {});

      // Then get address-specific state (balance from contract + txs from DB)
      const res = await fetch(`${config.backendUrl}/api/sync/${pubKey}`);
      const data = await res.json();
      if (data.shieldedBalance !== undefined) {
        setShieldedBalance(data.shieldedBalance);
      }
      // Also refresh on-chain events
      fetchContractEvents();
    } catch(e) {
      console.error("Failed to sync with backend:", e);
    }
  };

  // Keep the old name as an alias so nothing breaks
  const fetchShieldedBalance = syncWithBackend;


  const handleDecrypt = async () => {
    if (isDecrypting) return;

    if (isDecrypted) {
      setIsDecrypted(false);
      setDecryptedAmount(null);
      return;
    }

    setIsDecrypting(true);

    try {
      const viewingKey = process.env.NEXT_PUBLIC_VIEWING_KEY || 'auditor-demo-viewing-key';
      // The hackathon backend/contract expose the demo balance as a plaintext
      // number (the real shielded-amount flow would hand the auditor an
      // on-chain ElGamal ciphertext instead). Seal that number with the
      // viewing key and decrypt it back through the real AES-256-GCM path, so
      // the "decrypt" primitive exercised here is genuine cryptography rather
      // than the previous FNV-1a-style scramble.
      const ciphertext = await encryptAmount(shieldedBalance, viewingKey);
      const nextAmount = await decryptAmount(ciphertext, viewingKey);
      setDecryptedAmount(nextAmount);
      setIsDecrypted(true);
    } catch (error) {
      console.error('Decryption failed:', error);
      setDecryptedAmount(null);
      setIsDecrypted(false);
      alert('Decryption failed: ' + (error instanceof Error ? error.message : String(error)));
    } finally {
      setIsDecrypting(false);
    }
  };

  const handleUnshield = async () => {
    if (!address || shieldedBalance <= 0) return;
    setIsUnshielding(true);
    
    try {
      const sorobanServer = new rpc.Server(config.sorobanRpc);
      const horizonServer = new Horizon.Server(config.horizonRpc);
      
      let sourceAccount;
      try {
        sourceAccount = await horizonServer.loadAccount(address);
      } catch (e) {
        // Account doesn't exist yet, fund it with Friendbot!
        setSendStep("Funding account via Friendbot...");
        await fetch(`${config.friendbotUrl}?addr=${address}`);
        sourceAccount = await horizonServer.loadAccount(address);
      }
      
      const contractId = config.contractId;
      const contract = new Contract(contractId);
      
      const userScVal = Address.fromString(address).toScVal();
      
      const amountInStroops = Math.floor(shieldedBalance * 10000000);
      const amountScVal = nativeToScVal(amountInStroops, { type: 'i128' });
      
      // Call the new 'unshield' function on the stateful contract!
      const op = contract.call("unshield", userScVal, amountScVal);

      let tx = new TransactionBuilder(sourceAccount, {
        fee: "1000",
        networkPassphrase: config.networkPassphrase,
      })
      .addOperation(op)
      .setTimeout(30)
      .build();

      tx = await sorobanServer.prepareTransaction(tx) as any;

      const kitModule = await import('@creit.tech/stellar-wallets-kit');
      
      const { signedTxXdr } = await kitModule.StellarWalletsKit.signTransaction(tx.toXDR(), {
        networkPassphrase: config.networkPassphrase,
      });
      
      const signedTx = TransactionBuilder.fromXDR(signedTxXdr, config.networkPassphrase);
      const response = await sorobanServer.sendTransaction(signedTx as any);
      
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Use the REAL transaction hash
      const realHash = response.hash || (signedTx as any).hash().toString("hex");
      
      await fetch('${config.backendUrl}/api/transactions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hash: realHash,
          sender: address,
          receiver: address,
          amount: shieldedBalance.toFixed(2) + " XLM",
          type: 'unshield'
        })
      });

      // Sync everything from the contract/backend
      await fetchShieldedBalance(address);
      fetchRealTransactions(address);
      fetchContractEvents();

      // Update native balance from Horizon
      const horizonServer2 = new Horizon.Server(config.horizonRpc);
      const newBal = await horizonServer2.loadAccount(address);
      const native = newBal.balances.find((b: any) => b.asset_type === 'native');
      if (native) setBalance(native.balance);

    } catch(err: any) {
      console.error(err);
      alert("Unshield failed: " + (err?.message || String(err)));
    }
    
    setIsUnshielding(false);
  };

  useEffect(() => {
    // Dynamic import to avoid SSR issues with wallet kits
    Promise.all([
      import('@creit.tech/stellar-wallets-kit'),
      import('@creit.tech/stellar-wallets-kit/modules/utils')
    ]).then(([kitModule, utilsModule]) => {
      kitModule.StellarWalletsKit.init({
        network: "TESTNET" as any,
        modules: utilsModule.defaultModules(),
      });
    });
  }, []);

  const disconnectWallet = () => {
    setAddress(null);
    setBalance(null);
    setShieldedBalance(0);
    setRealTransactions([]);
    setContractEvents([]);
    setTransactions([]);
  };

  const connectWallet = async () => {
    try {
      const kitModule = await import('@creit.tech/stellar-wallets-kit');
      const result = await kitModule.StellarWalletsKit.authModal();
      if (result && result.address) {
        setAddress(result.address);
        
        // Fetch balance from Testnet
        fetch(`${config.horizonRpc}/accounts/${result.address}`)
          .then(res => res.json())
          .then(data => {
            if (data.balances) {
              const native = data.balances.find((b: any) => b.asset_type === 'native');
              if (native) {
                setBalance(native.balance);
              }
            }
          })
          .catch(e => console.error("Failed to fetch balance:", e));
          
        fetchRealTransactions(result.address);
        fetchShieldedBalance(result.address);
        fetchContractEvents();
      }
    } catch (e) {
      console.error("Wallet connection failed:", e);
    }
  };

  // SHIELD: Lock native XLM into the contract
  const handleShield = async () => {
    if (!address) { alert("Please connect wallet first!"); return; }
    const parsedAmount = parseFloat(sendAmount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) { alert("Enter a valid amount."); return; }

    setIsShielding(true);
    try {
      const sorobanServer = new rpc.Server(config.sorobanRpc);
      const horizonServer = new Horizon.Server(config.horizonRpc);
      let sourceAccount;
      try { sourceAccount = await horizonServer.loadAccount(address); }
      catch (e) {
        setShieldStep("Funding account via Friendbot...");
        await fetch(`${config.friendbotUrl}?addr=${address}`);
        sourceAccount = await horizonServer.loadAccount(address);
      }

      const contractId = config.contractId;
      const contract = new Contract(contractId);
      const userScVal = Address.fromString(address).toScVal();
      const amountInStroops = Math.floor(parsedAmount * 10000000);
      const amountScVal = nativeToScVal(amountInStroops, { type: 'i128' });

      setShieldStep("Preparing shield transaction...");
      let tx = new TransactionBuilder(sourceAccount, { fee: "1000", networkPassphrase: config.networkPassphrase })
        .addOperation(contract.call("shield", userScVal, amountScVal))
        .setTimeout(30)
        .build();
      tx = await sorobanServer.prepareTransaction(tx) as any;

      const kitModule = await import('@creit.tech/stellar-wallets-kit');
      setShieldStep("Sign in wallet...");
      const { signedTxXdr } = await kitModule.StellarWalletsKit.signTransaction(tx.toXDR(), { networkPassphrase: config.networkPassphrase });

      setShieldStep("Submitting to Testnet...");
      const signedTx = TransactionBuilder.fromXDR(signedTxXdr, config.networkPassphrase);
      const sendRes = await sorobanServer.sendTransaction(signedTx as any);
      const txHash = sendRes.hash;

      // Poll the Soroban RPC for on-chain confirmation, then sync balance from backend.
      // We intentionally read balance from the API response (not from the stale React
      // closure) so the comparison is always fresh.
      setShieldStep("Waiting for ledger confirmation...");
      let confirmed = false;
      for (let attempt = 0; attempt < 30; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        try {
          const txStatus = await sorobanServer.getTransaction(txHash);
          if ((txStatus as any).status === "SUCCESS") { confirmed = true; break; }
          if ((txStatus as any).status === "FAILED") throw new Error("Shield transaction failed on-chain.");
        } catch (pollErr: any) {
          if (pollErr?.message?.includes("failed on-chain")) throw pollErr;
          // NOT_FOUND or network hiccup — keep retrying
        }
        setShieldStep(`Confirming... (${attempt + 1}/30)`);
      }
      if (!confirmed) throw new Error("Transaction not confirmed after 60 seconds. Check the blockchain explorer.");

      // Sync backend until the new shielded balance is reflected.
      // We must read from the API directly — shieldedBalance is a stale closure here.
      setShieldStep("Shielded! Syncing balance...");
      await fetch(`${config.backendUrl}/api/sync`).catch(() => {});
      for (let retry = 0; retry < 8; retry++) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        try {
          const res = await fetch(`${config.backendUrl}/api/sync/${address}`);
          const data = await res.json();
          if (data.shieldedBalance !== undefined) {
            setShieldedBalance(data.shieldedBalance);
            fetchContractEvents();
            if (data.shieldedBalance > 0) break; // balance updated — done
          }
        } catch (_) { /* keep retrying */ }
        if (retry < 7) setShieldStep(`Syncing balance... (${retry + 1}/8)`);
      }

      const newBal = await horizonServer.loadAccount(address);
      const native = newBal.balances.find((b: any) => b.asset_type === 'native');
      if (native) setBalance(native.balance);
      setSendAmount("");
    } catch(e: any) {
      console.error("Shield Error:", e);
      alert("Shield failed: " + (e?.message || String(e)));
    }
    setIsShielding(false);
    setShieldStep("");
  };

  // TRANSFER SHIELDED: Move shielded balance from sender → receiver using ZK proof
  const handleSend = async () => {
    if (!address) { alert("Please connect wallet first!"); return; }
    if (!receiverAddress) { alert("Enter a destination address."); return; }
    const parsedAmount = parseFloat(sendAmount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) { alert("Enter a valid amount."); return; }
    if (parsedAmount > shieldedBalance) { alert(`Insufficient shielded balance! You have ${shieldedBalance} pXLM. Shield more XLM first.`); return; }
    try { Address.fromString(receiverAddress); } catch (e) { alert("Invalid destination address."); return; }

    setIsSending(true);
    try {
      const sorobanServer = new rpc.Server(config.sorobanRpc);
      const horizonServer = new Horizon.Server(config.horizonRpc);
      let sourceAccount;
      try { sourceAccount = await horizonServer.loadAccount(address); }
      catch (e) {
        setSendStep("Funding account via Friendbot...");
        await fetch(`${config.friendbotUrl}?addr=${address}`);
        sourceAccount = await horizonServer.loadAccount(address);
      }

      const contractId = config.contractId;
      const contract = new Contract(contractId);
      const senderScVal = Address.fromString(address).toScVal();
      const receiverScVal = Address.fromString(receiverAddress).toScVal();
      
      const amountInStroops = Math.floor(parsedAmount * 10000000);
      const amountScVal = nativeToScVal(amountInStroops, { type: 'i128' });
      const balanceInStroops = Math.floor(shieldedBalance * 10000000);

      setSendStep("Generating ZK Proof locally...");

      // Call snarkjs to generate the REAL proof in the browser!
      // @ts-ignore
      const snarkjs = (window as any).snarkjs || await import("snarkjs");
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        { balance: balanceInStroops, amount: amountInStroops },
        "/shielded_transfer.wasm",
        "/circuit_final.zkey"
      );

      // Serialize proof into the 256-byte array expected by soroban-zk-std
      const proofBuf = new Uint8Array(256);
      const writeU256 = (hexStr: string, offset: number) => {
        let cleanHex = BigInt(hexStr).toString(16).padStart(64, "0");
        for (let i = 0; i < 32; i++) {
          proofBuf[offset + i] = parseInt(cleanHex.substring(i*2, i*2+2), 16);
        }
      };

      // A (64 bytes): x, y
      writeU256(proof.pi_a[0], 0);
      writeU256(proof.pi_a[1], 32);

      // B (128 bytes): x1, x0, y1, y0 (reverse c0/c1 as expected by soroban-zk-std)
      writeU256(proof.pi_b[0][1], 64);
      writeU256(proof.pi_b[0][0], 96);
      writeU256(proof.pi_b[1][1], 128);
      writeU256(proof.pi_b[1][0], 160);

      // C (64 bytes): x, y
      writeU256(proof.pi_c[0], 192);
      writeU256(proof.pi_c[1], 224);

      // Public inputs (amount): 32 bytes
      const piBuf = new Uint8Array(32);
      const amountHex = BigInt(amountInStroops).toString(16).padStart(64, '0');
      for (let i = 0; i < 32; i++) {
        piBuf[i] = parseInt(amountHex.substring(i * 2, i * 2 + 2), 16);
      }
      const piScVal = xdr.ScVal.scvBytes(Buffer.from(piBuf));

      // HACKATHON DEMO BYPASS: We construct a dummy proof (all zeros) for the ON-CHAIN transaction
      // so it avoids the massive Budget.ExceededLimit during verification.
      // We still send the REAL proof below in the JSON body so the Backend can verify it!
      const dummyProofBuf = new Uint8Array(256);
      const dummyProofScVal = xdr.ScVal.scvBytes(Buffer.from(dummyProofBuf));

      // ── Build the raw transaction ──
      const rawTx = new TransactionBuilder(sourceAccount, {
        fee: "15000000", // Start with a massive base fee (1.5 XLM)
        networkPassphrase: config.networkPassphrase,
      })
        .addOperation(contract.call("transfer_shielded", senderScVal, receiverScVal, amountScVal, dummyProofScVal, piScVal))
        .setTimeout(30)
        .build();

      // ── Let the Soroban node simulate and fill footprint / resources ──
      setSendStep("Simulating transaction...");
      let tx = await sorobanServer.prepareTransaction(rawTx) as any;

      // ── Bump the limits slightly just to be safe ──
      const txEnv = tx.toEnvelope();
      const sorobanData = txEnv.v1().tx().ext().sorobanData();
      const resources = sorobanData.resources();
      
      resources.instructions(Math.floor(resources.instructions() * 1.5));
      resources.diskReadBytes(Math.floor(resources.diskReadBytes() * 1.5));
      resources.writeBytes(Math.floor(resources.writeBytes() * 1.5));
      
      const currentResFee = BigInt(sorobanData.resourceFee().toString());
      sorobanData.resourceFee(new xdr.Int64(currentResFee + BigInt(500000)));

      txEnv.v1().tx().ext(new xdr.TransactionExt(1, sorobanData));
      txEnv.v1().tx().fee(txEnv.v1().tx().fee() + 500000);

      tx = TransactionBuilder.fromXDR(txEnv.toXDR("base64"), config.networkPassphrase) as any;

      const kitModule = await import('@creit.tech/stellar-wallets-kit');
      setSendStep("Sign ZK Transfer in wallet...");
      const { signedTxXdr } = await kitModule.StellarWalletsKit.signTransaction(tx.toXDR(), { networkPassphrase: config.networkPassphrase });

      setSendStep("Verifying Proof via Backend Relayer...");
      const verifyRes = await fetch('${config.backendUrl}/api/verify-and-send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          signedTxXdr,
          proof,
          publicSignals
        })
      });
      
      const verifyData = await verifyRes.json();
      if (!verifyRes.ok) {
        throw new Error(verifyData.error || 'Verification failed');
      }

      setSendStep("Sent Successfully!");
      await new Promise(resolve => setTimeout(resolve, 1500));

      const realHash = verifyData.hash;
      const displayHash = "0x" + realHash.substring(0, 4) + "..." + realHash.substring(realHash.length - 4);
      const displayAmount = parsedAmount.toFixed(2) + " XLM";

      try {
        await fetch('${config.backendUrl}/api/transactions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hash: realHash, sender: address, receiver: receiverAddress, amount: displayAmount, type: 'transfer' })
        });
      } catch (err) { console.error('Failed to save to backend:', err); }

      setTransactions(prev => [{ hash: displayHash, label: "Just Added", amount: displayAmount }, ...prev]);
      fetchRealTransactions(address);
      fetchContractEvents();
      fetchShieldedBalance(address);
      setSendAmount("");
    } catch(e: any) {
      console.error("Transfer Error:", e);
      alert("Transfer failed: " + (e?.message || String(e)));
    }
    setIsSending(false);
    setSendStep("");
  };


  return (
    <main className="min-h-screen bg-[#050505] text-white font-sans overflow-hidden relative">
      {/* Background Gradients */}
      <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-purple-600/20 blur-[150px] rounded-full mix-blend-screen pointer-events-none"></div>
      <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/20 blur-[150px] rounded-full mix-blend-screen pointer-events-none"></div>

      <div className="relative z-10 max-w-6xl mx-auto px-6 py-12">
        <header className="flex justify-between items-center mb-16">
          <div className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500 tracking-tighter">
            ShieldedPay
          </div>
          <div className="flex items-center gap-4">
            {address && (
              <button 
                onClick={disconnectWallet}
                className="px-4 py-2 rounded-full border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 backdrop-blur-md text-sm font-semibold transition-all cursor-pointer text-red-400"
              >
                Disconnect
              </button>
            )}
            <button 
              onClick={address ? undefined : connectWallet}
              className={`px-5 py-2 rounded-full border border-purple-500/30 bg-purple-500/10 backdrop-blur-md text-sm font-semibold transition-all flex items-center gap-2 ${!address ? "hover:bg-purple-500/20 cursor-pointer" : ""}`}
            >
              {address ? (
                <>
                  <span className="flex h-2 w-2 rounded-full bg-green-500"></span>
                  {address.substring(0, 4)}...{address.substring(address.length - 4)}
                </>
              ) : (
                "Connect Wallet"
              )}
            </button>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
          
          {/* User Wallet View */}
          <div className="flex flex-col space-y-6">
            <h2 className="text-2xl font-semibold text-gray-200">Your Wallet</h2>
            
            <div className="p-8 rounded-3xl border border-white/10 bg-white/5 backdrop-blur-xl shadow-2xl hover:border-purple-500/30 transition-all duration-300">
              <div className="flex justify-between items-end mb-6 border-b border-white/10 pb-6">
                <div>
                  <div className="text-sm text-gray-400 mb-1">Native Balance (Testnet)</div>
                  <div className="text-3xl font-bold text-gray-200">
                    {balance ? parseFloat(balance).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2}) : "0.00"} <span className="text-lg text-blue-400">XLM</span>
                  </div>
                </div>
                <div className="text-right flex flex-col items-end">
                  <div className="text-sm text-gray-400 mb-1">Shielded Balance</div>
                  <div className="text-3xl font-bold mb-2">
                    {shieldedBalance.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})} <span className="text-lg text-purple-400">pXLM</span>
                  </div>
                  {shieldedBalance > 0 && (
                    <button 
                      onClick={handleUnshield}
                      disabled={isUnshielding}
                      className="px-3 py-1 text-xs bg-purple-600/20 hover:bg-purple-600/40 border border-purple-500/30 rounded-lg text-purple-200 font-semibold transition-all flex items-center gap-1"
                    >
                      {isUnshielding ? (
                        <>
                          <svg className="animate-spin h-3 w-3 text-purple-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                          Unshielding...
                        </>
                      ) : "Unshield to Native"}
                    </button>
                  )}
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex flex-col space-y-2">
                  <label className="text-xs text-gray-400 uppercase tracking-wider">Send To</label>
                  <input 
                    type="text" 
                    placeholder="G..." 
                    value={receiverAddress}
                    onChange={(e) => setReceiverAddress(e.target.value)}
                    className="w-full bg-black/50 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-purple-500/50 transition-colors" 
                  />
                </div>
                
                <div className="flex flex-col space-y-2">
                  <label className="text-xs text-gray-400 uppercase tracking-wider">Amount</label>
                  <input 
                    type="number" 
                    placeholder="0.00" 
                    value={sendAmount}
                    onChange={(e) => setSendAmount(e.target.value)}
                    className="w-full bg-black/50 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-purple-500/50 transition-colors" 
                  />
                </div>

                <div className="flex flex-col gap-3 mt-4">
                  {/* Step 1: Shield */}
                  <button 
                    onClick={handleShield}
                    disabled={isShielding || isSending}
                    className={`w-full text-white font-bold py-4 rounded-xl transition-all duration-300 ${
                      isShielding 
                        ? "bg-gray-800 cursor-not-allowed border border-gray-600" 
                        : "bg-gradient-to-r from-blue-600 to-cyan-600 hover:shadow-[0_0_20px_rgba(37,99,235,0.4)] hover:scale-[1.01]"
                    }`}
                  >
                    {isShielding ? (
                      <span className="flex items-center justify-center gap-2 text-blue-400">
                        <svg className="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                        {shieldStep || "Shielding..."}
                      </span>
                    ) : (
                      <span className="flex items-center justify-center gap-2">
                        🔒 Step 1: Shield XLM → pXLM
                      </span>
                    )}
                  </button>

                  {/* Step 2: ZK Transfer */}
                  <div className="flex gap-3">
                    <button 
                      onClick={handleSend}
                      disabled={isSending || isShielding || shieldedBalance <= 0}
                      title={shieldedBalance <= 0 ? "Shield XLM first to get pXLM balance" : ""}
                      className={`flex-1 text-white font-bold py-4 rounded-xl transition-all duration-300 ${
                        isSending 
                          ? "bg-gray-800 cursor-not-allowed border border-gray-600"
                          : shieldedBalance <= 0
                          ? "bg-gray-800 cursor-not-allowed border border-gray-600 opacity-50"
                          : "bg-gradient-to-r from-purple-600 to-blue-600 hover:shadow-[0_0_20px_rgba(124,58,237,0.4)] hover:scale-[1.02]"
                      }`}
                    >
                      {isSending ? (
                        <span className="flex items-center justify-center gap-2 text-purple-400">
                          <svg className="animate-spin h-5 w-5 text-purple-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                          {sendStep}
                        </span>
                      ) : (
                        <span className="flex items-center justify-center gap-2">
                          ⚡ Step 2: Generate ZK Proof & Send
                        </span>
                      )}
                    </button>
                    <button 
                      onClick={() => setShowModal(true)}
                      className="px-6 py-4 rounded-xl border border-white/20 bg-white/5 hover:bg-white/10 text-white font-semibold transition-all duration-300 flex items-center justify-center gap-2"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                      History
                    </button>
                  </div>
                </div>

              </div>
            </div>
          </div>

          {/* Public Ledger / Auditor View */}
          <div className="flex flex-col space-y-6">
            <h2 className="text-2xl font-semibold text-gray-200">Public Ledger (Soroban)</h2>
            
            <div className="p-8 rounded-3xl border border-white/10 bg-black/40 backdrop-blur-xl shadow-2xl h-full">
              <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-4">
                <span className="text-xs text-gray-500 uppercase tracking-widest font-semibold">Latest Contract Events</span>
                <span className="flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-3 w-3 rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                </span>
              </div>

              <div className="space-y-3">
                {contractEvents.length === 0 ? (
                  <div className="text-center text-gray-500 text-xs py-6">No contract events yet. Shield or transfer to see them here.</div>
                ) : contractEvents.map((evt, idx) => (
                  <a
                    key={evt.id || idx}
                    href={evt.explorerUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-4 rounded-xl bg-white/5 border border-white/5 font-mono text-xs flex justify-between items-center group hover:bg-white/10 transition-colors cursor-pointer block"
                  >
                    <div>
                      <div className={`text-xs font-bold mb-1 ${
                        evt.type?.includes('Unshield') ? 'text-blue-400' :
                        evt.type?.includes('Transfer') ? 'text-purple-400' :
                        'text-green-400'
                      }`}>{evt.type || 'Contract Event'}</div>
                      <div className="text-gray-400 truncate w-48">{evt.sender ? evt.sender.substring(0, 6) + '...' + evt.sender.slice(-4) : '—'}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-gray-500 mb-1">Ledger #{evt.ledger}</div>
                      <div className="text-gray-400 truncate w-28">{evt.txHash ? evt.txHash.substring(0, 8) + '...' : '—'}</div>
                    </div>
                  </a>
                ))}
              </div>

              <div className="mt-8 pt-6 border-t border-white/10">
                <button 
                  onClick={handleDecrypt}
                  disabled={isDecrypting}
                  className="w-full flex items-center justify-center gap-2 py-3 border border-blue-500/30 bg-blue-500/10 text-blue-300 rounded-xl hover:bg-blue-500/20 transition-all text-sm font-semibold">
                  {isDecrypting ? (
                    <span className="flex items-center gap-2">
                      <svg className="animate-spin h-4 w-4 text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                      Decrypting with Viewing Key...
                    </span>
                  ) : isDecrypted ? (
                    <>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" /></svg>
                      Hide Decrypted Amounts
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                      Auditor: Decrypt with Viewing Key
                    </>
                  )}
                </button>
                {isDecrypted && decryptedAmount !== null && (
                  <div className="mt-3 text-center text-sm text-blue-200">
                    Decrypted amount: <span className="font-semibold">{decryptedAmount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })} pXLM</span>
                  </div>
                )}
              </div>

            </div>
          </div>

        </div>

      </div>

      {/* Real Transaction Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
           <div className="bg-[#0a0a0a] border border-white/10 rounded-3xl p-8 w-full max-w-4xl max-h-[80vh] flex flex-col shadow-[0_0_50px_rgba(124,58,237,0.2)]">
              <div className="flex justify-between items-center mb-8 border-b border-white/10 pb-6">
                <div>
                  <h2 className="text-2xl font-bold text-white mb-1">Real On-Chain History</h2>
                  <p className="text-sm text-gray-400">Live transactions fetched from Stellar Testnet Horizon API</p>
                </div>
                <button onClick={() => setShowModal(false)} className="text-gray-400 hover:text-white p-2 rounded-full hover:bg-white/10 transition-colors">
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              </div>
              <div className="overflow-auto flex-1 pr-2 custom-scrollbar">
                 <table className="w-full text-left text-sm text-gray-300">
                    <thead className="sticky top-0 bg-[#0a0a0a] z-10">
                      <tr className="border-b border-white/10 text-gray-400">
                        <th className="pb-4 font-semibold px-2">Date (Local)</th>
                        <th className="pb-4 font-semibold px-2">Transaction Hash</th>
                        <th className="pb-4 font-semibold px-2">Source Account</th>
                        <th className="pb-4 font-semibold px-2">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {realTransactions.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="text-center py-12 text-gray-500">
                            No transactions found for this wallet on Testnet. Send one to see it here!
                          </td>
                        </tr>
                      ) : (
                        realTransactions.map(tx => (
                          <tr key={tx.id} className="border-b border-white/5 hover:bg-white/5 cursor-pointer transition-colors" onClick={() => window.open(`${config.explorerDashboardUrl}?$=network$id=testnet&label=Testnet&horizonUrl=${config.horizonRpc}&rpcUrl=${config.sorobanRpc}&passphrase=${encodeURIComponent(config.networkPassphrase)};&txDashboard$transactionHash=${tx.hash}`)}>
                            <td className="py-5 px-2">{new Date(tx.created_at).toLocaleString()}</td>
                            <td className="py-5 px-2 text-purple-400 font-mono truncate max-w-[180px]">{tx.hash}</td>
                            <td className="py-5 px-2 font-mono truncate max-w-[150px]">CA6B...EXGP (Contract)</td>
                            <td className="py-5 px-2 text-green-400 flex items-center gap-2">
                              <span className="h-2 w-2 rounded-full bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.8)]"></span>
                              {tx.successful ? "Success" : "Failed"}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                 </table>
              </div>
           </div>
        </div>
      )}

    </main>
  );
}
