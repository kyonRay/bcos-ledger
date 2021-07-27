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
 * @file StorageUtilities.cpp
 * @author: kyonRay
 * @date 2021-07-14
 */

#include "StorageUtilities.h"
#include "bcos-ledger/libledger/utilities/Common.h"
#include <bcos-framework/interfaces/protocol/CommonError.h>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

using namespace bcos;
using namespace bcos::protocol;
using namespace bcos::storage;

namespace bcos::ledger
{
std::string DirInfo::toString()
{
    std::stringstream ss;
    boost::archive::text_oarchive oa(ss);
    oa << *this;
    return ss.str();
}

bool DirInfo::fromString(DirInfo& _dir, std::string _str)
{
    std::stringstream ss(_str);
    try
    {
        boost::archive::text_iarchive ia(ss);
        ia >> _dir;
    }
    catch (boost::archive::archive_exception const& e)
    {
        LEDGER_LOG(ERROR) << LOG_BADGE("DirInfo::fromString") << LOG_DESC("deserialization error")
                          << LOG_KV("e.what", e.what()) << LOG_KV("str", _str);
        return false;
    }
    return true;
}

void StorageUtilities::createTables(const storage::TableFactoryInterface::Ptr& _tableFactory)
{
    auto configFields = SYS_VALUE + "," + SYS_CONFIG_ENABLE_BLOCK_NUMBER;
    auto consensusFields = NODE_TYPE + "," + NODE_WEIGHT + "," + NODE_ENABLE_NUMBER;

    _tableFactory->createTable(SYS_CONFIG, SYS_KEY, configFields);
    _tableFactory->createTable(SYS_CONSENSUS, "node_id", consensusFields);
    _tableFactory->createTable(SYS_CURRENT_STATE, SYS_KEY, SYS_VALUE);
    _tableFactory->createTable(SYS_HASH_2_TX, "tx_hash", SYS_VALUE);
    _tableFactory->createTable(SYS_HASH_2_NUMBER, "block_hash", SYS_VALUE);
    _tableFactory->createTable(SYS_NUMBER_2_HASH, "block_num", SYS_VALUE);
    _tableFactory->createTable(SYS_NUMBER_2_BLOCK_HEADER, "block_num", SYS_VALUE);
    _tableFactory->createTable(SYS_NUMBER_2_TXS, "block_num", SYS_VALUE);
    _tableFactory->createTable(SYS_HASH_2_RECEIPT, "block_num", SYS_VALUE);
    _tableFactory->createTable(SYS_BLOCK_NUMBER_2_NONCES, "block_num", SYS_VALUE);
    createFileSystemTables(_tableFactory);
    // db sync commit
    auto retPair = _tableFactory->commit();
    if ((retPair.second == nullptr || retPair.second->errorCode() == CommonError::SUCCESS) &&
        retPair.first > 0)
    {
        LEDGER_LOG(TRACE) << LOG_BADGE("createTables") << LOG_DESC("Storage commit success")
                          << LOG_KV("commitSize", retPair.first);
    }
    else
    {
        LEDGER_LOG(ERROR) << LOG_BADGE("createTables") << LOG_DESC("Storage commit error")
                          << LOG_KV("code", retPair.second->errorCode())
                          << LOG_KV("msg", retPair.second->errorMessage());
        BOOST_THROW_EXCEPTION(CreateSysTableFailed() << errinfo_comment(""));
    }
}

void StorageUtilities::createFileSystemTables(
    const storage::TableFactoryInterface::Ptr& _tableFactory)
{
    _tableFactory->createTable(FS_ROOT, SYS_KEY, SYS_VALUE);
    auto table = _tableFactory->openTable(FS_ROOT);
    auto typeEntry = table->newEntry();
    typeEntry->setField(SYS_VALUE, FS_TYPE_DIR);
    table->setRow(FS_KEY_TYPE, typeEntry);

    auto subEntry = table->newEntry();
    subEntry->setField(SYS_VALUE, DirInfo::emptyDirString());
    table->setRow(FS_KEY_SUB, subEntry);

    recursiveBuildDir(_tableFactory, FS_USER_BIN);
    recursiveBuildDir(_tableFactory, FS_USER_LOCAL);
    recursiveBuildDir(_tableFactory, FS_SYS_BIN);
    recursiveBuildDir(_tableFactory, FS_USER_DATA);
}
void StorageUtilities::recursiveBuildDir(
    const TableFactoryInterface::Ptr& _tableFactory, const std::string& _absoluteDir)
{
    if (_absoluteDir.empty())
    {
        return;
    }
    auto dirList = std::make_shared<std::vector<std::string>>();
    std::string absoluteDir = _absoluteDir;
    if (absoluteDir[0] == '/')
    {
        absoluteDir = absoluteDir.substr(1);
    }
    if (absoluteDir.at(absoluteDir.size() - 1) == '/')
    {
        absoluteDir = absoluteDir.substr(0, absoluteDir.size() - 1);
    }
    boost::split(*dirList, absoluteDir, boost::is_any_of("/"), boost::token_compress_on);
    std::string root = "/";
    DirInfo parentDir;
    for (auto& dir : *dirList)
    {
        auto table = _tableFactory->openTable(root);
        if (root != "/")
        {
            root += "/";
        }
        if (!table)
        {
            LEDGER_LOG(ERROR) << LOG_BADGE("recursiveBuildDir")
                              << LOG_DESC("can not open table root") << LOG_KV("root", root);
            return;
        }
        auto entry = table->getRow(FS_KEY_SUB);
        if (!entry)
        {
            LEDGER_LOG(ERROR) << LOG_BADGE("recursiveBuildDir")
                              << LOG_DESC("can get entry of FS_KEY_SUB") << LOG_KV("root", root);
            return;
        }
        auto subdirectories = entry->getField(SYS_VALUE);
        if (!DirInfo::fromString(parentDir, subdirectories))
        {
            LEDGER_LOG(ERROR) << LOG_BADGE("recursiveBuildDir") << LOG_DESC("parse error")
                              << LOG_KV("str", subdirectories);
            return;
        }
        FileInfo newDirectory(dir, FS_TYPE_DIR, 0);
        bool exist = false;
        for (const FileInfo& _f : parentDir.getSubDir())
        {
            if (_f.getName() == dir)
            {
                exist = true;
                break;
            }
        }
        if (exist)
        {
            root += dir;
            continue;
        }
        parentDir.getMutableSubDir().emplace_back(newDirectory);
        entry->setField(SYS_VALUE, parentDir.toString());
        table->setRow(FS_KEY_SUB, entry);

        std::string newDirPath = root + dir;
        _tableFactory->createTable(newDirPath, SYS_KEY, SYS_VALUE);
        auto newTable = _tableFactory->openTable(newDirPath);
        auto typeEntry = newTable->newEntry();
        typeEntry->setField(SYS_VALUE, FS_TYPE_DIR);
        newTable->setRow(FS_KEY_TYPE, typeEntry);

        auto subEntry = newTable->newEntry();
        subEntry->setField(SYS_VALUE, DirInfo::emptyDirString());
        newTable->setRow(FS_KEY_SUB, subEntry);

        auto numberEntry = newTable->newEntry();
        numberEntry->setField(SYS_VALUE, "0");
        newTable->setRow(FS_KEY_NUM, numberEntry);
        root += dir;
    }
}

bool StorageUtilities::syncTableSetter(
    const bcos::storage::TableFactoryInterface::Ptr& _tableFactory, const std::string& _tableName,
    const std::string& _row, const std::string& _fieldName, const std::string& _fieldValue)
{
    auto table = _tableFactory->openTable(_tableName);
    if (table)
    {
        auto entry = table->newEntry();
        entry->setField(_fieldName, _fieldValue);
        auto ret = table->setRow(_row, entry);

        LEDGER_LOG(TRACE) << LOG_BADGE("Write data to DB") << LOG_KV("openTable", _tableName)
                          << LOG_KV("row", _row) << LOG_KV("value", _fieldValue);
        return ret;
    }
    else
    {
        BOOST_THROW_EXCEPTION(OpenSysTableFailed() << errinfo_comment(_tableName));
    }
}

bool StorageUtilities::checkTableExist(
    const std::string& _tableName, const bcos::storage::TableFactoryInterface::Ptr& _tableFactory)
{
    auto table = _tableFactory->openTable(_tableName);
    return table != nullptr;
}

void StorageUtilities::asyncTableGetter(
    const bcos::storage::TableFactoryInterface::Ptr& _tableFactory, const std::string& _tableName,
    std::string _row, std::function<void(Error::Ptr, bcos::storage::Entry::Ptr)> _onGetEntry)
{
    auto table = _tableFactory->openTable(_tableName);
    if (!table)
    {
        LEDGER_LOG(DEBUG) << LOG_DESC("Open table error from db")
                          << LOG_KV("openTable", _tableName);
        auto error = std::make_shared<Error>(
            LedgerError::OpenTableFailed, "Open table failed, tableName: " + _tableName);
        _onGetEntry(error, nullptr);
        return;
    }

    LEDGER_LOG(TRACE) << LOG_BADGE("asyncTableGetter") << LOG_DESC("Get string from db")
                      << LOG_KV("openTable", _tableName) << LOG_KV("row", _row);
    table->asyncGetRow(_row, [_onGetEntry](const Error::Ptr& _error, Entry::Ptr _entry) {
        if (_error && _error->errorCode() != CommonError::SUCCESS)
        {
            auto error = std::make_shared<Error>(
                _error->errorCode(), "asyncGetRow callback error" + _error->errorMessage());
            _onGetEntry(error, nullptr);
            return;
        }
        // do not handle if entry is nullptr, just send it out
        _onGetEntry(nullptr, _entry);
    });
}
}  // namespace bcos::ledger
