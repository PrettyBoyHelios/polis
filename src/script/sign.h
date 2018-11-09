// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGN_H
#define BITCOIN_SCRIPT_SIGN_H

#include <boost/optional.hpp>
#include <hash.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <streams.h>
#include <script/standard.h>

class CKey;
class CKeyID;
class CKeyStore;
class CScript;
class CTransaction;

struct CMutableTransaction;

class SigningProvider
 {
 public:
     virtual ~SigningProvider() {}
     virtual bool GetCScript(const CScriptID &scriptid, CScript& script) const { return false; }
     virtual bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const { return false; }
     virtual bool GetKey(const CKeyID &address, CKey& key) const { return false; }
 };
 
 extern const SigningProvider& DUMMY_SIGNING_PROVIDER;
 
 class PublicOnlySigningProvider : public SigningProvider
 {
 private:
     const SigningProvider* m_provider;
 
 public:
     PublicOnlySigningProvider(const SigningProvider* provider) : m_provider(provider) {}
     bool GetCScript(const CScriptID &scriptid, CScript& script) const;
    bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const;
};

struct FlatSigningProvider final : public SigningProvider
{
    std::map<CScriptID, CScript> scripts;
    std::map<CKeyID, CPubKey> pubkeys;
    std::map<CKeyID, CKey> keys;
     bool GetCScript(const CScriptID& scriptid, CScript& script) const override;
    bool GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const override;
    bool GetKey(const CKeyID& keyid, CKey& key) const override;
};
FlatSigningProvider Merge(const FlatSigningProvider& a, const FlatSigningProvider& b);

/** Virtual base class for signature creators. */
class BaseSignatureCreator {
protected:
    const CKeyStore* keystore;

public:
    BaseSignatureCreator(const CKeyStore* keystoreIn) : keystore(keystoreIn) {}
    const CKeyStore& KeyStore() const { return *keystore; };
    virtual ~BaseSignatureCreator() {}
    virtual const BaseSignatureChecker& Checker() const =0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode) const =0;
};

/** A signature creator for transactions. */
class TransactionSignatureCreator : public BaseSignatureCreator {
    const CTransaction* txTo;
    unsigned int nIn;
    int nHashType;
    const TransactionSignatureChecker checker;

public:
    TransactionSignatureCreator(const CKeyStore* keystoreIn, const CTransaction* txToIn, unsigned int nInIn, int nHashTypeIn=SIGHASH_ALL);
    const BaseSignatureChecker& Checker() const  override{ return checker; }
    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode) const override;
};

/** A signature creator that just produces 72-byte empty signatures. */
class DummySignatureCreator : public BaseSignatureCreator {
public:
    DummySignatureCreator(const CKeyStore* keystoreIn) : BaseSignatureCreator(keystoreIn) {}
    const BaseSignatureChecker& Checker() const override;
    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode) const override;
};

/** Produce a script signature using a generic signature creator. */
bool ProduceSignature(const BaseSignatureCreator& creator, const CScript& scriptPubKey, CScript& scriptSig);

/** Produce a script signature for a transaction. */
bool SignSignature(const CKeyStore& keystore, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL);
bool SignSignature(const CKeyStore& keystore, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL);

/** Combine two script signatures using a generic signature checker, intelligently, possibly with OP_0 placeholders. */
CScript CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker, const CScript& scriptSig1, const CScript& scriptSig2);

/** Combine two script signatures on transactions. */
CScript CombineSignatures(const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn, const CScript& scriptSig1, const CScript& scriptSig2);

#endif // BITCOIN_SCRIPT_SIGN_H
