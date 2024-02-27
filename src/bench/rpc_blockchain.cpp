// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <bench/data.h>

#include <consensus/validation.h>
#include <llmq/chainlocks.h>
#include <llmq/context.h>
#include <llmq/instantsend.h>
#include <rpc/blockchain.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <univalue.h>

namespace {

struct TestBlockAndIndex {
    TestingSetup test_setup{};
    CBlock block{};
    uint256 blockHash{};
    CBlockIndex blockindex{};

    TestBlockAndIndex()
    {
        CDataStream stream(benchmark::data::block813851, SER_NETWORK, PROTOCOL_VERSION);
        char a = '\0';
        stream.write(&a, 1); // Prevent compaction

        stream >> block;

        blockHash = block.GetHash();
        blockindex.phashBlock = &blockHash;
        blockindex.nBits = 403014710;
    }
};

} // namespace

static void BlockToJsonVerbose(benchmark::Bench& bench)
{
    TestBlockAndIndex data;
    const LLMQContext& llmq_ctx = *data.test_setup.m_node.llmq_ctx;
    bench.run([&] {
        auto univalue = blockToJSON(data.block, &data.blockindex, &data.blockindex, *llmq_ctx.clhandler, *llmq_ctx.isman, /*verbose*/ true);
        ankerl::nanobench::doNotOptimizeAway(univalue);
    });
}

BENCHMARK(BlockToJsonVerbose);

static void BlockToJsonVerboseWrite(benchmark::Bench& bench)
{
    TestBlockAndIndex data;
    const LLMQContext& llmq_ctx = *data.test_setup.m_node.llmq_ctx;
    auto univalue = blockToJSON(data.block, &data.blockindex, &data.blockindex, *llmq_ctx.clhandler, *llmq_ctx.isman, /*verbose*/ true);
    bench.run([&] {
        auto str = univalue.write();
        ankerl::nanobench::doNotOptimizeAway(str);
    });
}

BENCHMARK(BlockToJsonVerboseWrite);
