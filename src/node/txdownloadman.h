// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXDOWNLOADMAN_H
#define BITCOIN_NODE_TXDOWNLOADMAN_H

#include <cstdint>
#include <memory>

class CBlock;
class CRollingBloomFilter;
class TxOrphanage;
class TxRequestTracker;
namespace node {
class TxDownloadManagerImpl;

class TxDownloadManager {
    const std::unique_ptr<TxDownloadManagerImpl> m_impl;

public:
    explicit TxDownloadManager();
    ~TxDownloadManager();

    // Get references to internal data structures. Outside access to these data structures should be
    // temporary and removed later once logic has been moved internally.
    TxOrphanage& GetOrphanageRef();
    TxRequestTracker& GetTxRequestRef();
    CRollingBloomFilter& RecentRejectsFilter();
    CRollingBloomFilter& RecentRejectsReconsiderableFilter();
    CRollingBloomFilter& RecentConfirmedTransactionsFilter();

    // Responses to chain events. TxDownloadManager is not an actual client of ValidationInterface, these are called through PeerManager.
    void ActiveTipChange();
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock);
    void BlockDisconnected();
};
} // namespace node
#endif // BITCOIN_NODE_TXDOWNLOADMAN_H
