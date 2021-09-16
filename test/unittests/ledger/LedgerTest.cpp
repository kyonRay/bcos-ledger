/**
 *  Copyright (C) 2021 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @file LedgerTest.cpp
 * @author: kyonRay
 * @date 2021-05-07
 */
#include "bcos-ledger/libledger/Ledger.h"
#include "bcos-ledger/libledger/utilities/BlockUtilities.h"
#include "common/FakeBlock.h"
#include "common/FakeTable.h"
#include "mock/MockKeyFactor.h"
#include <bcos-framework/testutils/TestPromptFixture.h>
#include <bcos-framework/testutils/crypto/HashImpl.h>
#include <boost/lexical_cast.hpp>
#include <boost/test/unit_test.hpp>

using namespace bcos;
using namespace bcos::ledger;
using namespace bcos::protocol;
using namespace bcos::storage;
using namespace bcos::crypto;

namespace bcos::test
{
class LedgerFixture : public TestPromptFixture
{
public:
    LedgerFixture() : TestPromptFixture()
    {
        m_storageGetter = StorageGetter::storageGetterFactory();
        m_storageSetter = StorageSetter::storageSetterFactory();
        m_blockFactory = createBlockFactory(createCryptoSuite());
        auto keyFactor = std::make_shared<MockKeyFactory>();
        m_blockFactory->cryptoSuite()->setKeyFactory(keyFactor);

        BOOST_CHECK(m_blockFactory != nullptr);
        BOOST_CHECK(m_blockFactory->blockHeaderFactory() != nullptr);
        BOOST_CHECK(m_blockFactory->transactionFactory() != nullptr);
        initStorage();
    }
    ~LedgerFixture()
    {
        if (m_ledger)
        {
            m_ledger->stop();
        }
    }

    inline void initStorage()
    {
        m_storage = std::make_shared<MockStorage>();
        BOOST_TEST(m_storage != nullptr);
        m_ledger = std::make_shared<Ledger>(m_blockFactory, m_storage);
        BOOST_CHECK(m_ledger != nullptr);
    }

    inline void initErrorStorage()
    {
        m_storage = std::make_shared<MockErrorStorage>();
        BOOST_TEST(m_storage != nullptr);
        m_ledger = std::make_shared<Ledger>(m_blockFactory, m_storage);
        BOOST_CHECK(m_ledger != nullptr);
    }

    inline void initFixture()
    {
        m_param = std::make_shared<LedgerConfig>();
        m_param->setBlockNumber(0);
        m_param->setHash(HashType(""));
        m_param->setBlockTxCountLimit(1000);
        m_param->setConsensusTimeout(1000);

        auto signImpl = std::make_shared<Secp256k1SignatureImpl>();
        consensus::ConsensusNodeList consensusNodeList;
        consensus::ConsensusNodeList observerNodeList;
        for (int i = 0; i < 4; ++i)
        {
            auto node = std::make_shared<consensus::ConsensusNode>(
                signImpl->generateKeyPair()->publicKey(), 10 + i);
            consensusNodeList.emplace_back(node);
        }
        auto observer_node = std::make_shared<consensus::ConsensusNode>(
            signImpl->generateKeyPair()->publicKey(), -1);
        observerNodeList.emplace_back(observer_node);

        m_param->setConsensusNodeList(consensusNodeList);
        m_param->setObserverNodeList(observerNodeList);

        auto tableFactory = getTableFactory(0);
        m_storage->addStateCache(0, tableFactory);
        auto result = m_ledger->buildGenesisBlock(m_param, 3000000000, "");
        BOOST_CHECK(result);
        auto result2 = m_ledger->buildGenesisBlock(m_param, 3000000000, "");
        BOOST_CHECK(result2);
    }

    inline void initEmptyFixture()
    {
        m_param = std::make_shared<LedgerConfig>();
        m_param->setBlockNumber(0);
        m_param->setHash(HashType(""));
        m_param->setBlockTxCountLimit(0);
        m_param->setConsensusTimeout(-1);

        auto tableFactory = getTableFactory(0);
        m_storage->addStateCache(0, tableFactory);
        auto result1 = m_ledger->buildGenesisBlock(m_param, 3000000000, "");
        BOOST_CHECK(!result1);
        m_param->setConsensusTimeout(10);
        auto result2 = m_ledger->buildGenesisBlock(m_param, 30, "");
        BOOST_CHECK(!result2);
        auto result3 = m_ledger->buildGenesisBlock(m_param, 3000000000, "");
        BOOST_CHECK(result3);
    }

    inline void initBlocks(int _number)
    {
        std::promise<bool> fakeBlockPromise;
        auto future = fakeBlockPromise.get_future();
        m_ledger->asyncGetBlockHashByNumber(
            0, [=, &fakeBlockPromise](Error::Ptr, const HashType& _hash) {
                m_fakeBlocks = fakeBlocks(
                    m_blockFactory->cryptoSuite(), m_blockFactory, 20, 20, _number, _hash.hex());
                fakeBlockPromise.set_value(true);
            });
        future.get();
    }

    inline void initEmptyBlocks(int _number)
    {
        std::promise<bool> fakeBlockPromise;
        auto future = fakeBlockPromise.get_future();
        m_ledger->asyncGetBlockHashByNumber(
            0, [=, &fakeBlockPromise](Error::Ptr, const HashType& _hash) {
                m_fakeBlocks = fakeEmptyBlocks(
                    m_blockFactory->cryptoSuite(), m_blockFactory, _number, _hash.hex());
                fakeBlockPromise.set_value(true);
            });
        future.get();
    }

    inline void initChain(int _number)
    {
        initBlocks(_number);
        auto negativeTable = getTableFactory(-1);
        m_storage->addStateCache(-1, negativeTable);
        for (int i = 0; i < _number; ++i)
        {
            auto table = getTableFactory(i + 1);
            auto txDataList = std::make_shared<std::vector<bytesPointer>>();
            auto txHashList = std::make_shared<protocol::HashList>();
            for (size_t j = 0; j < m_fakeBlocks->at(i)->transactionsSize(); ++j)
            {
                auto txData = m_fakeBlocks->at(i)->transaction(j)->encode(false);
                auto txPointer = std::make_shared<bytes>(txData.begin(), txData.end());
                txDataList->emplace_back(txPointer);
                txHashList->emplace_back(m_fakeBlocks->at(i)->transaction(j)->hash());
            }
            m_storage->addStateCache(i + 1, table);

            std::promise<bool> p1;
            auto f1 = p1.get_future();
            m_ledger->asyncStoreTransactions(txDataList, txHashList, [=, &p1](Error::Ptr _error) {
                BOOST_CHECK_EQUAL(_error, nullptr);
                p1.set_value(true);
            });
            BOOST_CHECK_EQUAL(f1.get(), true);

            std::promise<bool> p2;
            auto f2 = p2.get_future();
            m_ledger->asyncStoreReceipts(table, m_fakeBlocks->at(i), [=, &p2](Error::Ptr _error) {
                BOOST_CHECK_EQUAL(_error, nullptr);
                p2.set_value(true);
            });
            BOOST_CHECK_EQUAL(f2.get(), true);
        }

        for (int i = 0; i < _number; ++i)
        {
            std::promise<bool> p3;
            auto f3 = p3.get_future();
            m_ledger->asyncCommitBlock(m_fakeBlocks->at(i)->blockHeader(),
                [=, &p3](Error::Ptr _error, LedgerConfig::Ptr _config) {
                    BOOST_CHECK_EQUAL(_error, nullptr);
                    BOOST_CHECK_EQUAL(_config->blockNumber(), i + 1);
                    BOOST_CHECK(!_config->consensusNodeList().empty());
                    BOOST_CHECK(!_config->observerNodeList().empty());
                    p3.set_value(true);
                });

            BOOST_CHECK_EQUAL(f3.get(), true);
        }
    }

    inline void initEmptyChain(int _number)
    {
        initEmptyBlocks(_number);
        for (int i = 0; i < _number; ++i)
        {
            auto table = getTableFactory(i + 1);

            std::promise<bool> p2;
            auto f2 = p2.get_future();
            m_ledger->asyncStoreReceipts(table, m_fakeBlocks->at(i), [=, &p2](Error::Ptr _error) {
                BOOST_CHECK_EQUAL(_error, nullptr);
                p2.set_value(true);
            });
            BOOST_CHECK_EQUAL(f2.get(), true);

            std::promise<bool> p3;
            auto f3 = p3.get_future();
            m_ledger->asyncCommitBlock(m_fakeBlocks->at(i)->blockHeader(),
                [=, &p3](Error::Ptr _error, LedgerConfig::Ptr _config) {
                    BOOST_CHECK_EQUAL(_error, nullptr);
                    BOOST_CHECK_EQUAL(_config->blockNumber(), i + 1);
                    BOOST_CHECK(!_config->consensusNodeList().empty());
                    BOOST_CHECK(!_config->observerNodeList().empty());
                    p3.set_value(true);
                });

            BOOST_CHECK_EQUAL(f3.get(), true);
        }
    }

    inline TableFactoryInterface::Ptr getStateTable(const BlockNumber& _number)
    {
        auto hashImpl = std::make_shared<Keccak256Hash>();
        auto table = m_storage->getStateCache(_number);
        BOOST_CHECK(table != nullptr);
        return table;
    }
    inline TableFactoryInterface::Ptr getTableFactory(const BlockNumber& _number)
    {
        auto hashImpl = std::make_shared<Keccak256Hash>();
        auto table = std::make_shared<TableFactory>(m_storage, hashImpl, _number);
        BOOST_CHECK(table != nullptr);
        return table;
    }

    storage::StorageInterface::Ptr m_storage = nullptr;
    StorageSetter::Ptr m_storageSetter = nullptr;
    StorageGetter::Ptr m_storageGetter = nullptr;
    BlockFactory::Ptr m_blockFactory = nullptr;
    std::shared_ptr<Ledger> m_ledger = nullptr;
    LedgerConfig::Ptr m_param;
    BlocksPtr m_fakeBlocks;
};

BOOST_FIXTURE_TEST_SUITE(LedgerTest, LedgerFixture)

BOOST_AUTO_TEST_CASE(testFixtureLedger)
{
    initFixture();
    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetBlockNumber([&](Error::Ptr _error, BlockNumber _number) {
        BOOST_CHECK(_error == nullptr);
        BOOST_CHECK_EQUAL(_number, 0);
        p1.set_value(true);
    });

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    m_ledger->asyncGetBlockHashByNumber(0, [&](Error::Ptr _error, const crypto::HashType _hash) {
        BOOST_CHECK(_error == nullptr);
        BOOST_CHECK(_hash != HashType(""));
        m_ledger->asyncGetBlockNumberByHash(_hash, [&](Error::Ptr _error, BlockNumber _number) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_number, 0);
            p2.set_value(true);
        });
    });

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    m_ledger->asyncGetBlockDataByNumber(0, HEADER, [&](Error::Ptr _error, Block::Ptr _block) {
        BOOST_CHECK(_error == nullptr);
        BOOST_CHECK(_block != nullptr);
        BOOST_CHECK_EQUAL(_block->blockHeader()->number(), 0);
        p3.set_value(true);
    });

    std::promise<bool> p4;
    auto f4 = p4.get_future();
    m_ledger->asyncGetTotalTransactionCount(
        [&](Error::Ptr _error, int64_t _totalTxCount, int64_t _failedTxCount,
            protocol::BlockNumber _latestBlockNumber) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_totalTxCount, 0);
            BOOST_CHECK_EQUAL(_failedTxCount, 0);
            BOOST_CHECK_EQUAL(_latestBlockNumber, 0);
            p4.set_value(true);
        });

    std::promise<bool> p5;
    auto f5 = p5.get_future();
    m_ledger->asyncGetSystemConfigByKey(
        SYSTEM_KEY_TX_COUNT_LIMIT, [&](Error::Ptr _error, std::string _value, BlockNumber _number) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_value, "1000");
            BOOST_CHECK_EQUAL(_number, 0);
            p5.set_value(true);
        });

    std::promise<bool> p6;
    auto f6 = p6.get_future();
    m_ledger->asyncGetNodeListByType(
        CONSENSUS_OBSERVER, [&](Error::Ptr _error, consensus::ConsensusNodeListPtr _nodeList) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_nodeList->at(0)->nodeID()->hex(),
                m_param->observerNodeList().at(0)->nodeID()->hex());
            p6.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);
    BOOST_CHECK_EQUAL(f2.get(), true);
    BOOST_CHECK_EQUAL(f3.get(), true);
    BOOST_CHECK_EQUAL(f4.get(), true);
    BOOST_CHECK_EQUAL(f5.get(), true);
    BOOST_CHECK_EQUAL(f6.get(), true);
}

BOOST_AUTO_TEST_CASE(getBlockNumber)
{
    auto tableFactory = getTableFactory(0);
    m_storageSetter->createTables(tableFactory);
    m_storage->addStateCache(0, tableFactory);
    m_storageSetter->setCurrentState(getStateTable(0), SYS_KEY_CURRENT_NUMBER, "-1");
    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetBlockNumber([&](Error::Ptr _error, BlockNumber _number) {
        BOOST_CHECK(_error != nullptr);
        BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::CallbackError);
        BOOST_CHECK_EQUAL(_number, -1);
        p1.set_value(true);
    });
    BOOST_CHECK_EQUAL(f1.get(), true);
}

BOOST_AUTO_TEST_CASE(getBlockHashByNumber)
{
    initFixture();
    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetBlockHashByNumber(-1, [=, &p1](Error::Ptr _error, HashType _hash) {
        BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::ErrorArgument);
        BOOST_CHECK_EQUAL(_hash, HashType());
        p1.set_value(true);
    });

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    m_ledger->asyncGetBlockHashByNumber(1000, [=, &p2](Error::Ptr _error, HashType _hash) {
        BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::GetStorageError);
        BOOST_CHECK_EQUAL(_hash, HashType());
        p2.set_value(true);
    });

    auto table = getStateTable(0);
    m_storageSetter->setNumber2Hash(getStateTable(0), "0", "");
    table->commit();

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    m_ledger->asyncGetBlockHashByNumber(0, [=, &p3](Error::Ptr _error, HashType _hash) {
        BOOST_CHECK(_error == nullptr);
        BOOST_CHECK_EQUAL(_hash, HashType(""));
        p3.set_value(true);
    });
    BOOST_CHECK_EQUAL(f1.get(), true);
    BOOST_CHECK_EQUAL(f2.get(), true);
    BOOST_CHECK_EQUAL(f3.get(), true);
}

BOOST_AUTO_TEST_CASE(getBlockNumberByHash)
{
    initFixture();

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    // error hash
    m_ledger->asyncGetBlockNumberByHash(HashType(), [&](Error::Ptr _error, BlockNumber _number) {
        BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::GetStorageError);
        BOOST_CHECK_EQUAL(_number, -1);
        p1.set_value(true);
    });

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    m_ledger->asyncGetBlockNumberByHash(
        HashType("123"), [&](Error::Ptr _error, BlockNumber _number) {
            BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::GetStorageError);
            BOOST_CHECK_EQUAL(_number, -1);
            p2.set_value(true);
        });

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    m_storageGetter->getBlockHashByNumber(
        0, getStateTable(0), [&](Error::Ptr _error, bcos::storage::Entry::Ptr _hashEntry) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            auto table = getStateTable(0);
            m_storageSetter->setHash2Number(getStateTable(0), _hashEntry->getField(SYS_VALUE), "");
            table->commit();
            m_ledger->asyncGetBlockNumberByHash(HashType(_hashEntry->getField(SYS_VALUE)),
                [&](Error::Ptr _error, BlockNumber _number) {
                    BOOST_CHECK(_error != nullptr);
                    BOOST_CHECK_EQUAL(_number, -1);
                    p3.set_value(true);
                });
        });
    BOOST_CHECK_EQUAL(f1.get(), true);
    BOOST_CHECK_EQUAL(f2.get(), true);
    BOOST_CHECK_EQUAL(f3.get(), true);
}

BOOST_AUTO_TEST_CASE(getTotalTransactionCount)
{
    auto tableFactory = getTableFactory(0);
    m_storageSetter->createTables(tableFactory);
    m_storage->addStateCache(0, tableFactory);
    m_storageSetter->setCurrentState(getStateTable(0), SYS_KEY_TOTAL_TRANSACTION_COUNT, "");
    m_storageSetter->setCurrentState(getStateTable(0), SYS_KEY_TOTAL_FAILED_TRANSACTION, "");
    tableFactory->commit();

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetTotalTransactionCount(
        [&](Error::Ptr _error, int64_t totalCount, int64_t totalFailed,
            bcos::protocol::BlockNumber _number) {
            BOOST_CHECK(_error != nullptr);
            BOOST_CHECK_EQUAL(totalCount, -1);
            BOOST_CHECK_EQUAL(totalFailed, -1);
            BOOST_CHECK_EQUAL(_number, -1);
            p1.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);
}

BOOST_AUTO_TEST_CASE(getNodeListByType)
{
    initEmptyFixture();

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    // error type get empty node list
    m_ledger->asyncGetNodeListByType(
        "test", [&](Error::Ptr _error, consensus::ConsensusNodeListPtr _nodeList) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_nodeList->size(), 0);
            p1.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    m_ledger->asyncGetNodeListByType(
        CONSENSUS_SEALER, [&](Error::Ptr _error, consensus::ConsensusNodeListPtr _nodeList) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK(_nodeList != nullptr);
            BOOST_CHECK(_nodeList->size() == 0);
            p2.set_value(true);
        });
    BOOST_CHECK_EQUAL(f2.get(), true);

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    m_ledger->asyncGetNodeListByType(
        CONSENSUS_OBSERVER, [&](Error::Ptr _error, consensus::ConsensusNodeListPtr _nodeList) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK(_nodeList != nullptr);
            BOOST_CHECK(_nodeList->size() == 0);
            p3.set_value(true);
        });
    BOOST_CHECK_EQUAL(f3.get(), true);
}

BOOST_AUTO_TEST_CASE(testNodeListByType)
{
    initFixture();
    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetNodeListByType(
        CONSENSUS_SEALER, [&](Error::Ptr _error, consensus::ConsensusNodeListPtr _nodeList) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_nodeList->size(), 4);
            p1.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);

    consensus::ConsensusNodeList consensusNodeList;
    auto signImpl = std::make_shared<Secp256k1SignatureImpl>();
    auto node =
        std::make_shared<consensus::ConsensusNode>(signImpl->generateKeyPair()->publicKey(), 10);
    consensusNodeList.emplace_back(node);
    auto tableFactory = getTableFactory(0);
    m_storageSetter->setConsensusConfig(tableFactory, CONSENSUS_SEALER, consensusNodeList, "5");
    tableFactory->commit();

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    m_ledger->asyncGetNodeListByType(
        CONSENSUS_SEALER, [&](Error::Ptr _error, consensus::ConsensusNodeListPtr _nodeList) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_nodeList->size(), 4);
            p2.set_value(true);
        });
    BOOST_CHECK_EQUAL(f2.get(), true);

    initChain(5);

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    m_ledger->asyncGetNodeListByType(
        CONSENSUS_SEALER, [&](Error::Ptr _error, consensus::ConsensusNodeListPtr _nodeList) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_nodeList->size(), 5);
            p3.set_value(true);
        });
    BOOST_CHECK_EQUAL(f3.get(), true);
}

BOOST_AUTO_TEST_CASE(commit)
{
    initFixture();
    initChain(5);

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    // test isBlockShouldCommit
    m_ledger->asyncCommitBlock(
        m_fakeBlocks->at(3)->blockHeader(), [&](Error::Ptr _error, LedgerConfig::Ptr _config) {
            BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::ErrorCommitBlock);
            BOOST_CHECK(_config == nullptr);
            p1.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    // null header in storage
    m_ledger->asyncCommitBlock(nullptr, [&](Error::Ptr _error, LedgerConfig::Ptr _config) {
        BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::ErrorArgument);
        BOOST_CHECK(_config == nullptr);
        p2.set_value(true);
    });
    BOOST_CHECK_EQUAL(f2.get(), true);
}

BOOST_AUTO_TEST_CASE(parallelCommitSameBlock)
{
    initFixture();
    initChain(1);
    auto block = fakeBlock(m_blockFactory->cryptoSuite(), m_blockFactory, 20, 20, 2);
    ParentInfo parentInfo;
    parentInfo.blockNumber = 1;
    parentInfo.blockHash = m_fakeBlocks->at(0)->blockHeader()->hash();
    ParentInfoList parentInfoList;
    parentInfoList.emplace_back(parentInfo);
    block->blockHeader()->setNumber(2);
    block->blockHeader()->setParentInfo(parentInfoList);

    // test parallel commit
    auto table = getTableFactory(2);
    auto txDataList = std::make_shared<std::vector<bytesPointer>>();
    auto txHashList = std::make_shared<protocol::HashList>();
    for (size_t j = 0; j < block->transactionsSize(); ++j)
    {
        auto txData = block->transaction(j)->encode(false);
        auto txPointer = std::make_shared<bytes>(txData.begin(), txData.end());
        txDataList->emplace_back(txPointer);
        txHashList->emplace_back(block->transaction(j)->hash());
    }
    m_storage->addStateCache(2, table);

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncStoreTransactions(txDataList, txHashList, [=, &p1](Error::Ptr _error) {
        BOOST_CHECK_EQUAL(_error, nullptr);
        p1.set_value(true);
    });
    BOOST_CHECK_EQUAL(f1.get(), true);

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    m_ledger->asyncStoreReceipts(table, block, [=, &p2](Error::Ptr _error) {
        BOOST_CHECK_EQUAL(_error, nullptr);
        p2.set_value(true);
    });
    BOOST_CHECK_EQUAL(f2.get(), true);

    BCOS_LOG(INFO) << LOG_BADGE("TEST") << LOG_DESC("==============Commit==============");
    int testTimes = 10;

    auto success_count = std::make_shared<std::atomic_int>();
    auto count = std::make_shared<std::atomic_int>();
    *success_count = 0;
    *count = 0;
    tbb::parallel_for(
        tbb::blocked_range<size_t>(0, testTimes), [&](const tbb::blocked_range<size_t>& _r) {
            for (auto i = _r.begin(); i < _r.end(); ++i)
            {
                m_ledger->asyncCommitBlock(
                    block->blockHeader(), [&](Error::Ptr _error, LedgerConfig::Ptr _config) {
                        if (_error)
                        {
                            BOOST_CHECK(_error->errorCode() == LedgerError::ErrorCommitBlock);
                            BCOS_LOG(INFO) << LOG_BADGE("TEST") << LOG_DESC(_error->errorMessage());
                        }
                        if (_config)
                        {
                            BOOST_CHECK_EQUAL(_config->blockNumber(), 2);
                            BOOST_CHECK(!_config->consensusNodeList().empty());
                            BOOST_CHECK(!_config->observerNodeList().empty());
                            success_count->fetch_add(1);
                        }
                        count->fetch_add(1);
                    });
            }
        });
    while (true)
    {
        if (count->load() == testTimes)
        {
            break;
        }
    }
    // only success once
    BOOST_CHECK(success_count->load() == 1);
}

BOOST_AUTO_TEST_CASE(parallelCommit)
{
    initFixture();
    int blockNumber = 20;
    initBlocks(blockNumber);

    // test parallel commit 20 blocks
    auto negativeTable = getTableFactory(-1);
    m_storage->addStateCache(-1, negativeTable);
    for (int i = 0; i < blockNumber; ++i)
    {
        auto table = getTableFactory(i + 1);
        auto txDataList = std::make_shared<std::vector<bytesPointer>>();
        auto txHashList = std::make_shared<protocol::HashList>();
        for (size_t j = 0; j < m_fakeBlocks->at(i)->transactionsSize(); ++j)
        {
            auto txData = m_fakeBlocks->at(i)->transaction(j)->encode(false);
            auto txPointer = std::make_shared<bytes>(txData.begin(), txData.end());
            txDataList->emplace_back(txPointer);
            txHashList->emplace_back(m_fakeBlocks->at(i)->transaction(j)->hash());
        }
        m_storage->addStateCache(i + 1, table);

        std::promise<bool> p1;
        auto f1 = p1.get_future();
        m_ledger->asyncStoreTransactions(txDataList, txHashList, [=, &p1](Error::Ptr _error) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            p1.set_value(true);
        });
        BOOST_CHECK_EQUAL(f1.get(), true);

        std::promise<bool> p2;
        auto f2 = p2.get_future();
        m_ledger->asyncStoreReceipts(table, m_fakeBlocks->at(i), [=, &p2](Error::Ptr _error) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            p2.set_value(true);
        });
        BOOST_CHECK_EQUAL(f2.get(), true);
    }
    BCOS_LOG(INFO) << LOG_BADGE("TEST") << LOG_DESC("==============Commit==============");

    auto blockQueue = std::make_shared<std::queue<protocol::Block::Ptr>>();
    for (int i = 0; i < blockNumber; ++i)
    {
        blockQueue->push(m_fakeBlocks->at(i));
    }
    auto count = std::make_shared<std::atomic_int>();
    *count = 0;
    while (!blockQueue->empty())
    {
        auto number = blockQueue->size();
        auto blockVector = std::make_shared<std::vector<Block::Ptr>>();
        for (size_t i = 0; i < number; ++i)
        {
            blockVector->push_back(blockQueue->front());
            blockQueue->pop();
        }
        tbb::parallel_for(tbb::blocked_range<size_t>(0, number),
            [&, blockQueue, blockVector, count](const tbb::blocked_range<size_t>& _r) {
                for (auto i = _r.begin(); i < _r.end(); ++i)
                {
                    auto block = blockVector->at(i);
                    std::promise<bool> p;
                    m_ledger->asyncCommitBlock(
                        block->blockHeader(), [&, block, blockQueue, count](
                                                  Error::Ptr _error, LedgerConfig::Ptr _config) {
                            if (_error)
                            {
                                BOOST_CHECK(_error->errorCode() == LedgerError::ErrorCommitBlock);
                                BCOS_LOG(INFO)
                                    << LOG_BADGE("TEST") << LOG_DESC(_error->errorMessage());
                                blockQueue->push(block);
                            }
                            if (_config)
                            {
                                BCOS_LOG(INFO) << LOG_BADGE("TEST")
                                               << LOG_KV("commitNumber", _config->blockNumber());
                                count->fetch_add(1);
                            }
                            p.set_value(true);
                        });
                    p.get_future().get();
                }
            });
        BCOS_LOG(INFO) << LOG_BADGE("TEST") << LOG_KV("queueSize", blockQueue->size());
    }
    while (true)
    {
        if (count->load() == blockNumber)
        {
            break;
        }
    }

    std::promise<bool> promise;
    m_ledger->asyncGetBlockNumber([&](Error::Ptr, BlockNumber _number) {
        BOOST_CHECK(_number == blockNumber);
        promise.set_value(true);
    });
    BOOST_CHECK(promise.get_future().get() == true);
}


BOOST_AUTO_TEST_CASE(errorStorage)
{
    initErrorStorage();
    initEmptyFixture();
    auto newBlock = fakeBlock(m_blockFactory->cryptoSuite(), m_blockFactory, 1, 1, 1);
    ParentInfoList fakeParentInfoList;
    ParentInfo fakeParent;

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetBlockHashByNumber(0, [&](Error::Ptr, const HashType& _hash) {
        fakeParent.blockHash = HashType(_hash);
        fakeParent.blockNumber = 0;
        fakeParentInfoList.emplace_back(fakeParent);
        newBlock->blockHeader()->setParentInfo(fakeParentInfoList);
        p1.set_value(true);
    });
    BOOST_CHECK_EQUAL(f1.get(), true);

    auto table = std::make_shared<TableFactory>(m_storage, nullptr, 1);
    m_storage->addStateCache(1, table);

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    m_ledger->asyncCommitBlock(
        newBlock->blockHeader(), [=, &p2](Error::Ptr _error, LedgerConfig::Ptr _config) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK(_config != nullptr);
            p2.set_value(true);
        });
    BOOST_CHECK_EQUAL(f2.get(), true);

    auto bytesPtr = std::make_shared<bytes>(asBytes(""));
    auto bytesList = std::make_shared<std::vector<bytesPointer>>();
    bytesList->emplace_back(bytesPtr);
    auto hashList = std::make_shared<protocol::HashList>();
    hashList->emplace_back(HashType(""));

    // force store to trigger random error
    for (int i = 0; i < 10; ++i)
    {
        std::promise<bool> p;
        auto f = p.get_future();
        m_ledger->asyncStoreTransactions(bytesList, hashList, [&](Error::Ptr _error) {
            BOOST_CHECK(_error != nullptr);
            p.set_value(true);
        });
        BOOST_CHECK_EQUAL(f.get(), true);

        std::promise<bool> pp;
        auto ff = pp.get_future();
        m_ledger->asyncStoreReceipts(getStateTable(0), newBlock, [&](Error::Ptr _error) {
            BOOST_CHECK(_error != nullptr);
            pp.set_value(true);
        });
        BOOST_CHECK_EQUAL(ff.get(), true);
    }
}

BOOST_AUTO_TEST_CASE(getBlockDataByNumber)
{
    initFixture();
    // test cache
    initChain(20);

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    // error number
    m_ledger->asyncGetBlockDataByNumber(
        1000, FULL_BLOCK, [=, &p1](Error::Ptr _error, Block::Ptr _block) {
            BOOST_CHECK(_error != nullptr);
            BOOST_CHECK_EQUAL(_block, nullptr);
            p1.set_value(true);
        });

    std::promise<bool> pp1;
    auto ff1 = pp1.get_future();
    m_ledger->asyncGetBlockDataByNumber(
        -1, FULL_BLOCK, [=, &pp1](Error::Ptr _error, Block::Ptr _block) {
            BOOST_CHECK(_error != nullptr);
            BOOST_CHECK_EQUAL(_block, nullptr);
            pp1.set_value(true);
        });

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    // cache hit
    m_ledger->asyncGetBlockDataByNumber(
        15, FULL_BLOCK, [=, &p2](Error::Ptr _error, Block::Ptr _block) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK(_block->blockHeader() != nullptr);
            BOOST_CHECK(_block->transactionsSize() != 0);
            BOOST_CHECK(_block->receiptsSize() != 0);
            p2.set_value(true);
        });

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    // cache not hit
    m_ledger->asyncGetBlockDataByNumber(
        3, FULL_BLOCK, [=, &p3](Error::Ptr _error, Block::Ptr _block) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK(_block->blockHeader() != nullptr);
            BOOST_CHECK(_block->transactionsSize() != 0);
            BOOST_CHECK(_block->receiptsSize() != 0);
            p3.set_value(true);
        });

    std::promise<bool> p4;
    auto f4 = p4.get_future();
    m_ledger->asyncGetBlockDataByNumber(
        5, TRANSACTIONS, [=, &p4](Error::Ptr _error, Block::Ptr _block) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK(_block->transactionsSize() != 0);
            p4.set_value(true);
        });

    std::promise<bool> p5;
    auto f5 = p5.get_future();
    m_ledger->asyncGetBlockDataByNumber(
        5, RECEIPTS, [=, &p5](Error::Ptr _error, Block::Ptr _block) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK(_block->receiptsSize() != 0);
            p5.set_value(true);
        });

    std::promise<bool> p6;
    auto f6 = p6.get_future();
    m_ledger->asyncGetBlockDataByNumber(
        0, TRANSACTIONS, [=, &p6](Error::Ptr _error, Block::Ptr _block) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK_EQUAL(_block->transactionsSize(), 0);
            p6.set_value(true);
        });

    std::promise<bool> p7;
    auto f7 = p7.get_future();
    m_ledger->asyncGetBlockDataByNumber(
        0, RECEIPTS, [=, &p7](Error::Ptr _error, Block::Ptr _block) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK_EQUAL(_block->receiptsSize(), 0);
            p7.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);
    BOOST_CHECK_EQUAL(ff1.get(), true);
    BOOST_CHECK_EQUAL(f2.get(), true);
    BOOST_CHECK_EQUAL(f3.get(), true);
    BOOST_CHECK_EQUAL(f4.get(), true);
    BOOST_CHECK_EQUAL(f5.get(), true);
    BOOST_CHECK_EQUAL(f6.get(), true);
    BOOST_CHECK_EQUAL(f7.get(), true);
}

BOOST_AUTO_TEST_CASE(getTransactionByHash)
{
    initFixture();
    initChain(5);
    auto hashList = std::make_shared<protocol::HashList>();
    auto errorHashList = std::make_shared<protocol::HashList>();
    auto fullHashList = std::make_shared<protocol::HashList>();
    hashList->emplace_back(m_fakeBlocks->at(3)->transactionHash(0));
    hashList->emplace_back(m_fakeBlocks->at(3)->transactionHash(1));
    hashList->emplace_back(m_fakeBlocks->at(4)->transactionHash(0));
    errorHashList->emplace_back(HashType("123"));
    errorHashList->emplace_back(HashType("456"));
    fullHashList->emplace_back(m_fakeBlocks->at(3)->transactionHash(0));
    fullHashList->emplace_back(m_fakeBlocks->at(3)->transactionHash(1));
    fullHashList->emplace_back(m_fakeBlocks->at(3)->transactionHash(2));
    fullHashList->emplace_back(m_fakeBlocks->at(3)->transactionHash(3));

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetBatchTxsByHashList(hashList, true,
        [=, &p1](Error::Ptr _error, protocol::TransactionsPtr _txList,
            std::shared_ptr<std::map<std::string, MerkleProofPtr>> _proof) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK(_txList != nullptr);
            BOOST_CHECK(_proof->at(m_fakeBlocks->at(3)->transaction(0)->hash().hex()) != nullptr);
            p1.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    m_ledger->asyncGetBatchTxsByHashList(fullHashList, true,
        [=, &p2](Error::Ptr _error, protocol::TransactionsPtr _txList,
            std::shared_ptr<std::map<std::string, MerkleProofPtr>> _proof) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK(_txList != nullptr);
            BOOST_CHECK(_proof->at(m_fakeBlocks->at(3)->transaction(0)->hash().hex()) != nullptr);
            p2.set_value(true);
        });
    BOOST_CHECK_EQUAL(f2.get(), true);

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    // error hash list
    m_ledger->asyncGetBatchTxsByHashList(errorHashList, true,
        [=, &p3](Error::Ptr _error, protocol::TransactionsPtr _txList,
            std::shared_ptr<std::map<std::string, MerkleProofPtr>> _proof) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK(_txList != nullptr);
            BOOST_CHECK(_txList->empty());
            BOOST_CHECK(_proof != nullptr);
            BOOST_CHECK(_proof->empty());
            p3.set_value(true);
        });
    BOOST_CHECK_EQUAL(f3.get(), true);

    std::promise<bool> p4;
    auto f4 = p4.get_future();
    // without proof
    m_ledger->asyncGetBatchTxsByHashList(hashList, false,
        [=, &p4](Error::Ptr _error, protocol::TransactionsPtr _txList,
            std::shared_ptr<std::map<std::string, MerkleProofPtr>> _proof) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK(_txList != nullptr);
            BOOST_CHECK(_proof == nullptr);
            p4.set_value(true);
        });
    BOOST_CHECK_EQUAL(f4.get(), true);

    std::promise<bool> p5;
    auto f5 = p5.get_future();
    // null hash list
    m_ledger->asyncGetBatchTxsByHashList(nullptr, false,
        [=, &p5](Error::Ptr _error, protocol::TransactionsPtr _txList,
            std::shared_ptr<std::map<std::string, MerkleProofPtr>> _proof) {
            BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::ErrorArgument);
            BOOST_CHECK(_txList == nullptr);
            BOOST_CHECK(_proof == nullptr);
            p5.set_value(true);
        });
    BOOST_CHECK_EQUAL(f5.get(), true);
}

BOOST_AUTO_TEST_CASE(getTransactionReceiptByHash)
{
    initFixture();
    initChain(5);

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetTransactionReceiptByHash(m_fakeBlocks->at(3)->transactionHash(0), true,
        [&](Error::Ptr _error, TransactionReceipt::ConstPtr _receipt, MerkleProofPtr _proof) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK_EQUAL(
                _receipt->hash().hex(), m_fakeBlocks->at(3)->receipt(0)->hash().hex());
            BOOST_CHECK(_proof != nullptr);
            p1.set_value(true);
        });

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    // without proof
    m_ledger->asyncGetTransactionReceiptByHash(m_fakeBlocks->at(3)->transactionHash(0), false,
        [&](Error::Ptr _error, TransactionReceipt::ConstPtr _receipt, MerkleProofPtr _proof) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK_EQUAL(
                _receipt->hash().hex(), m_fakeBlocks->at(3)->receipt(0)->hash().hex());
            BOOST_CHECK(_proof == nullptr);
            p2.set_value(true);
        });

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    // error hash
    m_ledger->asyncGetTransactionReceiptByHash(HashType(), false,
        [&](Error::Ptr _error, TransactionReceipt::ConstPtr _receipt, MerkleProofPtr _proof) {
            BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::GetStorageError);
            BOOST_CHECK_EQUAL(_receipt, nullptr);
            BOOST_CHECK(_proof == nullptr);
            p3.set_value(true);
        });

    std::promise<bool> p4;
    auto f4 = p4.get_future();
    m_ledger->asyncGetTransactionReceiptByHash(HashType("123"), true,
        [&](Error::Ptr _error, TransactionReceipt::ConstPtr _receipt, MerkleProofPtr _proof) {
            BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::GetStorageError);
            BOOST_CHECK_EQUAL(_receipt, nullptr);
            BOOST_CHECK(_proof == nullptr);
            p4.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);
    BOOST_CHECK_EQUAL(f2.get(), true);
    BOOST_CHECK_EQUAL(f3.get(), true);
    BOOST_CHECK_EQUAL(f4.get(), true);
}

BOOST_AUTO_TEST_CASE(getNonceList)
{
    initFixture();
    initChain(5);

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetNonceList(3, 6,
        [&](Error::Ptr _error,
            std::shared_ptr<std::map<protocol::BlockNumber, protocol::NonceListPtr>> _nonceMap) {
            BOOST_CHECK_EQUAL(_error, nullptr);
            BOOST_CHECK(_nonceMap != nullptr);
            BOOST_CHECK_EQUAL(_nonceMap->size(), 3);
            p1.set_value(true);
        });

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    // error param
    m_ledger->asyncGetNonceList(-1, -5,
        [&](Error::Ptr _error,
            std::shared_ptr<std::map<protocol::BlockNumber, protocol::NonceListPtr>> _nonceMap) {
            BOOST_CHECK(_error != nullptr);
            BOOST_CHECK(_nonceMap == nullptr);
            p2.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);
    BOOST_CHECK_EQUAL(f2.get(), true);
}

BOOST_AUTO_TEST_CASE(preStoreTransaction)
{
    initFixture();
    initBlocks(5);
    auto txBytesList = std::make_shared<std::vector<bytesPointer>>();
    auto hashList = std::make_shared<crypto::HashList>();
    for (size_t i = 0; i < m_fakeBlocks->at(3)->transactionsSize(); ++i)
    {
        auto txData = m_fakeBlocks->at(3)->transaction(i)->encode();
        auto txPointer = std::make_shared<bytes>(txData.toBytes());
        auto hash = m_fakeBlocks->at(3)->transaction(i)->hash();
        txBytesList->emplace_back(txPointer);
        hashList->emplace_back(hash);
    }

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncStoreTransactions(txBytesList, hashList, [&](Error::Ptr _error) {
        BOOST_CHECK_EQUAL(_error, nullptr);
        p1.set_value(true);
    });

    std::promise<bool> p2;
    auto f2 = p2.get_future();
    // null pointer
    m_ledger->asyncStoreTransactions(txBytesList, nullptr, [&](Error::Ptr _error) {
        BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::ErrorArgument);
        p2.set_value(true);
    });

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    m_ledger->asyncStoreTransactions(nullptr, hashList, [&](Error::Ptr _error) {
        BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::ErrorArgument);
        p3.set_value(true);
    });
    BOOST_CHECK_EQUAL(f1.get(), true);
    BOOST_CHECK_EQUAL(f2.get(), true);
    BOOST_CHECK_EQUAL(f3.get(), true);
}

BOOST_AUTO_TEST_CASE(preStoreReceipt)
{
    initFixture();
    initBlocks(5);

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncStoreReceipts(nullptr, m_fakeBlocks->at(1), [&](Error::Ptr _error) {
        BOOST_CHECK_EQUAL(_error->errorCode(), LedgerError::ErrorArgument);
        p1.set_value(true);
    });
    BOOST_CHECK_EQUAL(f1.get(), true);
}

BOOST_AUTO_TEST_CASE(getSystemConfig)
{
    initFixture();

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetSystemConfigByKey(
        SYSTEM_KEY_TX_COUNT_LIMIT, [&](Error::Ptr _error, std::string _value, BlockNumber _number) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_value, "1000");
            BOOST_CHECK_EQUAL(_number, 0);
            p1.set_value(true);
        });
    BOOST_CHECK_EQUAL(f1.get(), true);

    auto tableFactory = getTableFactory(0);
    m_storageSetter->setSysConfig(tableFactory, SYSTEM_KEY_TX_COUNT_LIMIT, "2000", "5");
    tableFactory->commit();

    std::promise<bool> pp1;
    m_ledger->asyncGetSystemConfigByKey(
        SYSTEM_KEY_TX_COUNT_LIMIT, [&](Error::Ptr _error, std::string _value, BlockNumber _number) {
            BOOST_CHECK(_error != nullptr);
            BOOST_CHECK_EQUAL(_value, "");
            BOOST_CHECK_EQUAL(_number, -1);
            pp1.set_value(true);
        });
    BOOST_CHECK_EQUAL(pp1.get_future().get(), true);

    initChain(5);

    std::promise<bool> pp2;
    m_ledger->asyncGetSystemConfigByKey(
        SYSTEM_KEY_TX_COUNT_LIMIT, [&](Error::Ptr _error, std::string _value, BlockNumber _number) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK_EQUAL(_value, "2000");
            BOOST_CHECK_EQUAL(_number, 5);
            pp2.set_value(true);
        });
    BOOST_CHECK_EQUAL(pp2.get_future().get(), true);

    std::promise<bool> p3;
    auto f3 = p3.get_future();
    // get error key
    m_ledger->asyncGetSystemConfigByKey(
        "test", [&](Error::Ptr _error, std::string _value, BlockNumber _number) {
            BOOST_CHECK(_error->errorCode() == LedgerError::GetStorageError);
            BOOST_CHECK_EQUAL(_value, "");
            BOOST_CHECK_EQUAL(_number, -1);
            p3.set_value(true);
        });
    BOOST_CHECK_EQUAL(f3.get(), true);
}

BOOST_AUTO_TEST_CASE(testDecode)
{
    auto block = decodeBlock(m_blockFactory, "");
    auto tx = decodeTransaction(m_blockFactory->transactionFactory(), "");
    auto header = decodeBlockHeader(m_blockFactory->blockHeaderFactory(), "");
    auto receipt = decodeReceipt(m_blockFactory->receiptFactory(), "");
}

BOOST_AUTO_TEST_CASE(testEmptyBlock)
{
    initFixture();
    initEmptyChain(20);

    std::promise<bool> p1;
    auto f1 = p1.get_future();
    m_ledger->asyncGetBlockDataByNumber(
        4, FULL_BLOCK, [&](Error::Ptr _error, bcos::protocol::Block::Ptr _block) {
            BOOST_CHECK(_error == nullptr);
            BOOST_CHECK(_block != nullptr);
            p1.set_value(true);
        });
    BOOST_CHECK(f1.get());
}

BOOST_AUTO_TEST_SUITE_END()
}  // namespace bcos::test
