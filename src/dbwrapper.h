// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_DBWRAPPER_H
#define SYSCOIN_DBWRAPPER_H

#include <attributes.h>
#include <clientversion.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <util/check.h>
#include <util/fs.h>

#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

static const size_t DBWRAPPER_PREALLOC_KEY_SIZE = 64;
static const size_t DBWRAPPER_PREALLOC_VALUE_SIZE = 1024;

//! User-controlled performance and debug options.
struct DBOptions {
    //! Compact database on startup.
    bool force_compact = false;
};

//! Application-specific storage settings.
struct DBParams {
    //! Location in the filesystem where leveldb data will be stored.
    fs::path path;
    //! Configures various leveldb cache settings.
    size_t cache_bytes;
    //! If true, use leveldb's memory environment.
    bool memory_only = false;
    //! If true, remove all existing data.
    bool wipe_data = false;
    //! If true, store data obfuscated via simple XOR. If false, XOR with a
    //! zero'd byte array.
    bool obfuscate = false;
    //! Passed-through options.
    DBOptions options{};
};

class dbwrapper_error : public std::runtime_error
{
public:
    explicit dbwrapper_error(const std::string& msg) : std::runtime_error(msg) {}
};

class CDBWrapper;

/** These should be considered an implementation detail of the specific database.
 */
namespace dbwrapper_private {

/** Work around circular dependency, as well as for testing in dbwrapper_tests.
 * Database obfuscation should be considered an implementation detail of the
 * specific database.
 */
const std::vector<unsigned char>& GetObfuscateKey(const CDBWrapper &w);

}; // namespace dbwrapper_private

bool DestroyDB(const std::string& path_str);

/** Batch of changes queued to be written to a CDBWrapper */
class CDBBatch
{
    friend class CDBWrapper;

private:
    const CDBWrapper &parent;

    struct WriteBatchImpl;
    const std::unique_ptr<WriteBatchImpl> m_impl_batch;

    DataStream ssKey{};
    CDataStream ssValue;

    size_t size_estimate{0};

    void WriteImpl(Span<const std::byte> key, CDataStream& ssValue);
    void EraseImpl(Span<const std::byte> key);

public:
    /**
     * @param[in] _parent   CDBWrapper that this batch is to be submitted to
     */
    explicit CDBBatch(const CDBWrapper& _parent);
    ~CDBBatch();
    void Clear();

    template <typename K, typename V>
    void Write(const K& key, const V& value)
    {
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssValue.reserve(DBWRAPPER_PREALLOC_VALUE_SIZE);
        ssKey << key;
        ssValue << value;
        WriteImpl(ssKey, ssValue);
        ssKey.clear();
        ssValue.clear();
    }

    template <typename K>
    void Erase(const K& key)
    {
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        EraseImpl(ssKey);
        ssKey.clear();
    }

    size_t SizeEstimate() const { return size_estimate; }
};

class CDBIterator
{
public:
    struct IteratorImpl;

private:
    const CDBWrapper &parent;
    const std::unique_ptr<IteratorImpl> m_impl_iter;

    void SeekImpl(Span<const std::byte> key);
    Span<const std::byte> GetKeyImpl() const;
    Span<const std::byte> GetValueImpl() const;

public:

    /**
     * @param[in] _parent          Parent CDBWrapper instance.
     * @param[in] _piter           The original leveldb iterator.
     */
    CDBIterator(const CDBWrapper& _parent, std::unique_ptr<IteratorImpl> _piter);
    ~CDBIterator();

    bool Valid() const;

    void SeekToFirst();

    template<typename K> void Seek(const K& key) {
        DataStream ssKey{};
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        SeekImpl(ssKey);
    }

    void Next();

    template<typename K> bool GetKey(K& key) {
        try {
            DataStream ssKey{GetKeyImpl()};
            ssKey >> key;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }
    // SYSCOIN
    CDataStream GetKey() {
        leveldb::Slice slKey = piter->key();
        return CDataStream(MakeUCharSpan(slKey), SER_DISK, CLIENT_VERSION);
    }
    template<typename V> bool GetValue(V& value) {
        try {
            CDataStream ssValue{GetValueImpl(), SER_DISK, CLIENT_VERSION};
            ssValue.Xor(dbwrapper_private::GetObfuscateKey(parent));
            ssValue >> value;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }
};

struct LevelDBContext;

class CDBWrapper
{
    friend const std::vector<unsigned char>& dbwrapper_private::GetObfuscateKey(const CDBWrapper &w);
private:
    //! holds all leveldb-specific fields of this class
    std::unique_ptr<LevelDBContext> m_db_context;

    //! the name of this database
    std::string m_name;

    //! a key used for optional XOR-obfuscation of the database
    std::vector<unsigned char> obfuscate_key;

    //! the key under which the obfuscation key is stored
    static const std::string OBFUSCATE_KEY_KEY;

    //! the length of the obfuscate key in number of bytes
    static const unsigned int OBFUSCATE_KEY_NUM_BYTES;

    std::vector<unsigned char> CreateObfuscateKey() const;

    //! path to filesystem storage
    const fs::path m_path;

    //! whether or not the database resides in memory
    bool m_is_memory;

    std::optional<std::string> ReadImpl(Span<const std::byte> key) const;
    bool ExistsImpl(Span<const std::byte> key) const;
    size_t EstimateSizeImpl(Span<const std::byte> key1, Span<const std::byte> key2) const;
    auto& DBContext() const LIFETIMEBOUND { return *Assert(m_db_context); }

public:
    CDBWrapper(const DBParams& params);
    ~CDBWrapper();

    CDBWrapper(const CDBWrapper&) = delete;
    CDBWrapper& operator=(const CDBWrapper&) = delete;
    // SYSCOIN
    template <typename K>
    bool ReadDataStream(const K& key, CDataStream& ssValue) const
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        return ReadDataStream(ssKey, ssValue);
    }

    bool ReadDataStream(const CDataStream& ssKey, CDataStream& ssValue) const
    {
        leveldb::Slice slKey((const char*)ssKey.data(), ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            dbwrapper_private::HandleError(status);
        }
        CDataStream ssValueTmp(MakeUCharSpan(strValue), SER_DISK, CLIENT_VERSION);
        ssValueTmp.Xor(obfuscate_key);
        ssValue = std::move(ssValueTmp);
        return true;
    }
    template <typename K, typename V>
    bool Read(const K& key, V& value) const
    {
        DataStream ssKey{};
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        std::optional<std::string> strValue{ReadImpl(ssKey)};
        if (!strValue) {
            return false;
        }
        try {
            CDataStream ssValue{MakeByteSpan(*strValue), SER_DISK, CLIENT_VERSION};
            ssValue.Xor(obfuscate_key);
            ssValue >> value;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    template <typename K, typename V>
    bool Write(const K& key, const V& value, bool fSync = false)
    {
        CDBBatch batch(*this);
        batch.Write(key, value);
        return WriteBatch(batch, fSync);
    }

    //! @returns filesystem path to the on-disk data.
    std::optional<fs::path> StoragePath() {
        if (m_is_memory) {
            return {};
        }
        return m_path;
    }

    template <typename K>
    bool Exists(const K& key) const
    {
        DataStream ssKey{};
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        return ExistsImpl(ssKey);
    }

    template <typename K>
    bool Erase(const K& key, bool fSync = false)
    {
        CDBBatch batch(*this);
        batch.Erase(key);
        return WriteBatch(batch, fSync);
    }

    bool WriteBatch(CDBBatch& batch, bool fSync = false);

    // Get an estimate of LevelDB memory usage (in bytes).
    size_t DynamicMemoryUsage() const;

    CDBIterator* NewIterator();

    /**
     * Return true if the database managed by this class contains no entries.
     */
    bool IsEmpty();

    template<typename K>
    size_t EstimateSize(const K& key_begin, const K& key_end) const
    {
        DataStream ssKey1{}, ssKey2{};
        ssKey1.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey2.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey1 << key_begin;
        ssKey2 << key_end;
        return EstimateSizeImpl(ssKey1, ssKey2);
    }
};
// SYSCOIN

template<typename CDBTransaction>
class CDBTransactionIterator
{
private:
    CDBTransaction& transaction;

    typedef typename std::remove_pointer<decltype(transaction.parent.NewIterator())>::type ParentIterator;

    // We maintain 2 iterators, one for the transaction and one for the parent
    // At all times, only one of both provides the current value. The decision is made by comparing the current keys
    // of both iterators, so that always the smaller key is the current one. On Next(), the previously chosen iterator
    // is advanced.
    typename CDBTransaction::WritesMap::iterator transactionIt;
    std::unique_ptr<ParentIterator> parentIt;
    CDataStream parentKey;
    bool curIsParent{false};

public:
    explicit CDBTransactionIterator(CDBTransaction& _transaction) :
            transaction(_transaction),
            parentKey(SER_DISK, CLIENT_VERSION)
    {
        transactionIt = transaction.writes.end();
        parentIt = std::unique_ptr<ParentIterator>(transaction.parent.NewIterator());
    }

    void SeekToFirst() {
        transactionIt = transaction.writes.begin();
        parentIt->SeekToFirst();
        SkipDeletedAndOverwritten();
        DecideCur();
    }

    template<typename K>
    void Seek(const K& key) {
        Seek(CDBTransaction::KeyToDataStream(key));
    }

    void Seek(const CDataStream& ssKey) {
        transactionIt = transaction.writes.lower_bound(ssKey);
        parentIt->Seek(ssKey);
        SkipDeletedAndOverwritten();
        DecideCur();
    }

    bool Valid() {
        return transactionIt != transaction.writes.end() || parentIt->Valid();
    }

    void Next() {
        if (transactionIt == transaction.writes.end() && !parentIt->Valid()) {
            return;
        }
        if (curIsParent) {
            assert(parentIt->Valid());
            parentIt->Next();
            SkipDeletedAndOverwritten();
        } else {
            assert(transactionIt != transaction.writes.end());
            ++transactionIt;
        }
        DecideCur();
    }

    template<typename K>
    bool GetKey(K& key) {
        if (!Valid()) {
            return false;
        }

        if (curIsParent) {
            try {
                // TODO try to avoid this copy (we need a stream that allows reading from external buffers)
                CDataStream ssKey = parentKey;
                ssKey >> key;
            } catch (const std::exception&) {
                return false;
            }
            return true;
        } else {
            try {
                // TODO try to avoid this copy (we need a stream that allows reading from external buffers)
                CDataStream ssKey = transactionIt->first;
                ssKey >> key;
            } catch (const std::exception&) {
                return false;
            }
            return true;
        }
    }

    CDataStream GetKey() {
        if (!Valid()) {
            return CDataStream(SER_DISK, CLIENT_VERSION);
        }
        if (curIsParent) {
            return parentKey;
        } else {
            return transactionIt->first;
        }
    }

    unsigned int GetKeySize() {
        if (!Valid()) {
            return 0;
        }
        if (curIsParent) {
            return parentIt->GetKeySize();
        } else {
            return transactionIt->first.vKey.size();
        }
    }

    template<typename V>
    bool GetValue(V& value) {
        if (!Valid()) {
            return false;
        }
        if (curIsParent) {
            return transaction.Read(parentKey, value);
        } else {
            return transaction.Read(transactionIt->first, value);
        }
    };

private:
    void SkipDeletedAndOverwritten() {
        while (parentIt->Valid()) {
            parentKey = parentIt->GetKey();	            
            if (!transaction.deletes.count(parentKey) && !transaction.writes.count(parentKey)) {	
                break;
            }
            parentIt->Next();
        }
    }

    void DecideCur() {
        if (transactionIt != transaction.writes.end() && !parentIt->Valid()) {
            curIsParent = false;
        } else if (transactionIt == transaction.writes.end() && parentIt->Valid()) {
            curIsParent = true;
        } else if (transactionIt != transaction.writes.end() && parentIt->Valid()) {
            if (CDBTransaction::DataStreamCmp::less(transactionIt->first, parentKey)) {
                curIsParent = false;
            } else {
                curIsParent = true;
            }
        }
    }
};

template<typename Parent, typename CommitTarget>
class CDBTransaction {
    friend class CDBTransactionIterator<CDBTransaction>;

protected:
    Parent &parent;
    CommitTarget &commitTarget;
    ssize_t memoryUsage{0}; // signed, just in case we made an error in the calculations so that we don't get an overflow

    struct DataStreamCmp {
        static bool less(const CDataStream& a, const CDataStream& b) {
            return std::lexicographical_compare(
                    (const uint8_t*)a.data(), (const uint8_t*)a.data() + a.size(),
                    (const uint8_t*)b.data(), (const uint8_t*)b.data() + b.size());
        }
        bool operator()(const CDataStream& a, const CDataStream& b) const {
            return less(a, b);
        }
    };

    struct ValueHolder {
        size_t memoryUsage;
        explicit ValueHolder(size_t _memoryUsage) : memoryUsage(_memoryUsage) {}
        virtual ~ValueHolder() = default;
        virtual void Write(const CDataStream& ssKey, CommitTarget &parent) = 0;
    };
    typedef std::unique_ptr<ValueHolder> ValueHolderPtr;

    template <typename V>
    struct ValueHolderImpl : ValueHolder {
        ValueHolderImpl(const V &_value, size_t _memoryUsage) : ValueHolder(_memoryUsage), value(_value) {}

        virtual void Write(const CDataStream& ssKey, CommitTarget &commitTarget) override {
            // we're moving the value instead of copying it. This means that Write() can only be called once per
            // ValueHolderImpl instance. Commit() clears the write maps, so this ok.
            commitTarget.Write(ssKey, std::move(value));
        }
        V value;
    };

    template<typename K>
    static CDataStream KeyToDataStream(const K& key) {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        return ssKey;
    }

    typedef std::map<CDataStream, ValueHolderPtr, DataStreamCmp> WritesMap;
    typedef std::set<CDataStream, DataStreamCmp> DeletesSet;

    WritesMap writes;
    DeletesSet deletes;

public:
    CDBTransaction(Parent &_parent, CommitTarget &_commitTarget) : parent(_parent), commitTarget(_commitTarget) {}

    template <typename K, typename V>
    void Write(const K& key, const V& v) {
        Write(KeyToDataStream(key), v);
    }

    template <typename V>
    void Write(const CDataStream& ssKey, const V& v) {
        auto valueMemoryUsage = ::GetSerializeSize(v, CLIENT_VERSION);

        if (deletes.erase(ssKey)) {
            memoryUsage -= ssKey.size();
        }
        auto it = writes.emplace(ssKey, nullptr).first;
        if (it->second) {
            memoryUsage -= ssKey.size() + it->second->memoryUsage;
        }
        it->second = std::make_unique<ValueHolderImpl<V>>(v, valueMemoryUsage);

        memoryUsage += ssKey.size() + valueMemoryUsage;
    }

    template <typename K, typename V>
    bool Read(const K& key, V& value) {
        return Read(KeyToDataStream(key), value);
    }

    template <typename V>
    bool Read(const CDataStream& ssKey, V& value) {
        if (deletes.count(ssKey)) {
            return false;
        }

        auto it = writes.find(ssKey);
        if (it != writes.end()) {
            auto *impl = dynamic_cast<ValueHolderImpl<V> *>(it->second.get());
            if (!impl) {
                throw std::runtime_error("Read called with V != previously written type");
            }
            value = impl->value;
            return true;
        }

        return parent.Read(ssKey, value);
    }

    template <typename K>
    bool Exists(const K& key) {
        return Exists(KeyToDataStream(key));
    }

    bool Exists(const CDataStream& ssKey) {
        if (deletes.count(ssKey)) {
            return false;
        }

        if (writes.count(ssKey)) {
            return true;
        }

        return parent.Exists(ssKey);
    }

    template <typename K>
    void Erase(const K& key) {
        return Erase(KeyToDataStream(key));
    }

    void Erase(const CDataStream& ssKey) {
        auto it = writes.find(ssKey);
        if (it != writes.end()) {
            memoryUsage -= ssKey.size() + it->second->memoryUsage;
            writes.erase(it);
        }
        if (deletes.emplace(ssKey).second) {
            memoryUsage += ssKey.size();
        }
    }

    void Clear() {
        writes.clear();
        deletes.clear();
        memoryUsage = 0;
    }

    void Commit() {
        for (const auto &k : deletes) {
            commitTarget.Erase(k);
        }
        for (auto &p : writes) {
            p.second->Write(p.first, commitTarget);
        }
        Clear();
    }

    bool IsClean() const {
        return writes.empty() && deletes.empty();
    }

    size_t GetMemoryUsage() const {
        if (memoryUsage < 0) {
            // something went wrong when we accounted/calculated used memory...
            static volatile bool didPrint = false;
            if (!didPrint) {
                LogPrintf("CDBTransaction::%s -- negative memoryUsage (%d)", __func__, memoryUsage);
                didPrint = true;
            }
            return 0;
        }
        return (size_t)memoryUsage;
    }

    CDBTransactionIterator<CDBTransaction>* NewIterator() {
        return new CDBTransactionIterator<CDBTransaction>(*this);
    }
    std::unique_ptr<CDBTransactionIterator<CDBTransaction>> NewIteratorUniquePtr() {
        return std::make_unique<CDBTransactionIterator<CDBTransaction>>(*this);
    }
};

#endif // SYSCOIN_DBWRAPPER_H
