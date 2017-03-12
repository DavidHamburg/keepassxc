#include "testgpg.h"
#include <QTest>
#include <QStringList>

QTEST_GUILESS_MAIN(TestGpg)

void TestGpg::testGetAvailableSecretKeys()
{
    Gpg sut;

    std::vector<GpgEncryptionKey> list;
    sut.getAvailableSecretKeys(list);

    for (auto &element : list){
        qDebug() << element.toString();
    }

    QCOMPARE(list.size(), std::size_t(4));
}
