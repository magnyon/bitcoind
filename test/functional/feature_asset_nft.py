#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import decimal
from test_framework.test_framework import SyscoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

class AssetNFTTest(SyscoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.rpc_timeout = 240
        self.extra_args = [['-assetindex=1'],['-assetindex=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.nodes[0].generate(200)
        self.basic_assetnft()
        self.basic_multiassetnft()

    def GetBaseAssetID(self, nAsset):
        return (nAsset & 0xFFFFFFFF)

    def GetNFTID(self, nAsset):
        return nAsset >> 32

    def CreateAssetID(self, NFTID, nBaseAsset):
        return (NFTID << 32) | nBaseAsset

    def basic_assetnft(self):
        asset = self.nodes[0].assetnew('1', 'NFT', 'asset nft description', '0x', 8, 10000, 127, '', {}, {})['asset_guid']
        self.sync_mempools()
        self.nodes[1].generate(3)
        self.sync_blocks()
        self.nodes[0].assetsend(asset, self.nodes[1].getnewaddress(), 1.1, 1)
        self.nodes[0].generate(3)
        self.sync_blocks()
        nftGuid = self.CreateAssetID(1, asset)
        out = self.nodes[1].listunspent(query_options={'assetGuid': nftGuid, 'minimumAmountAsset': 1.1})
        assert_equal(len(out), 1)

    def basic_multiassetnft(self):
        asset = self.nodes[0].assetnew('1', 'NFT', 'asset nft description', '0x', 8, 10000, 127, '', {}, {})['asset_guid']
        self.sync_mempools()
        self.nodes[1].generate(3)
        self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1)
        self.sync_blocks()
        nftUser1 = 1
        nftUser2 = 2
        nftUser4 = 0xFFFFFFFF
        # NFT 1
        user1 = self.nodes[1].getnewaddress()
        # NFT 2
        user2 = self.nodes[1].getnewaddress()
        # normal asset
        user3 = self.nodes[1].getnewaddress()
        # NFT 0xFFFFFFFF
        user4 = self.nodes[1].getnewaddress()
        self.nodes[0].assetsendmany(asset,[{'address': user1,'amount':0.00000001,'NFTID':nftUser1},{'address': user2,'amount':0.4,'NFTID':nftUser2},{'address': user3,'amount':0.5},{'address': user4,'amount':0.6,'NFTID':nftUser4}])
        self.nodes[0].generate(3)
        self.sync_blocks()
        nftGuidUser1 = self.CreateAssetID(nftUser1, asset)
        nftGuidUser2 = self.CreateAssetID(nftUser2, asset)
        nftGuidUser4 = self.CreateAssetID(nftUser4, asset)
        out = self.nodes[0].listunspentasset(nftGuidUser1)
        assert_equal(len(out), 0)
        out = self.nodes[1].listunspentasset(nftGuidUser1)
        assert_equal(len(out), 1)
        assert_equal(out[0]['asset_guid'], nftGuidUser1)
        assert_equal(out[0]['asset_amount'], decimal.Decimal('0.00000001'))
        out = self.nodes[1].listunspentasset(nftGuidUser2)
        assert_equal(len(out), 1)
        assert_equal(out[0]['asset_guid'], nftGuidUser2)
        assert_equal(out[0]['asset_amount'], decimal.Decimal('0.4'))
        out = self.nodes[1].listunspentasset(asset)
        assert_equal(len(out), 1)
        assert_equal(out[0]['asset_guid'], asset)
        assert_equal(out[0]['asset_amount'], decimal.Decimal('0.5'))
        out = self.nodes[1].listunspentasset(nftGuidUser4)
        assert_equal(len(out), 1)
        assert_equal(out[0]['asset_guid'], nftGuidUser4)
        assert_equal(out[0]['asset_amount'], decimal.Decimal('0.6'))
        assert_raises_rpc_error(-4, 'Insufficient funds', self.nodes[1].assetallocationsend, nftGuidUser1, self.nodes[0].getnewaddress(), 0.00000002)
        assert_raises_rpc_error(-26, 'bad-txns-asset-io-mismatch', self.nodes[1].assetallocationsend, nftGuidUser1, self.nodes[0].getnewaddress(), 0.00000000)
        assert_raises_rpc_error(-4, 'Insufficient funds', self.nodes[1].assetallocationsend, nftGuidUser2, self.nodes[0].getnewaddress(), 0.5)
        assert_raises_rpc_error(-4, 'Insufficient funds', self.nodes[1].assetallocationsend, asset, self.nodes[0].getnewaddress(), 0.6)
        self.nodes[1].assetallocationsend(nftGuidUser1, self.nodes[0].getnewaddress(), 0.00000001)
        self.nodes[1].generate(1)
        self.sync_blocks()
        out = self.nodes[1].listunspentasset(nftGuidUser1)
        assert_equal(len(out), 0)
        out = self.nodes[0].listunspentasset(nftGuidUser1)
        assert_equal(len(out), 1)
        assert_equal(out[0]['asset_guid'], nftGuidUser1)
        assert_equal(out[0]['asset_amount'], decimal.Decimal('0.00000001'))
        
if __name__ == '__main__':
    AssetNFTTest().main()
