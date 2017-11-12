#include "testgpg.h"
#include <QStringList>
#include <QTest>

QTEST_GUILESS_MAIN(TestGpg)

void TestGpg::initTestCase()
{
    Gpg gpg;
    std::vector<GpgEncryptionKey> keys;
    gpg.getAvailableSecretKeys(keys);

    if (keys.size() == 0) {
        QSKIP("No gpg key available. Skipping tests", SkipAll);
    } else {
        m_key = keys.front();
    }
}

void TestGpg::testGetAvailableSecretKeys()
{
    Gpg sut;
    std::vector<GpgEncryptionKey> list;
    sut.getAvailableSecretKeys(list);

    QVERIFY(list.size() > 0);
}

void TestGpg::testGetKeyById()
{
    Gpg sut;
    auto result = sut.getKeyById(m_key.getId());
    QCOMPARE(m_key.getId(), result.getId());
}
