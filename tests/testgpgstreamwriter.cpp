#include "testgpgstreamwriter.h"
#include "crypto/Crypto.h"
#include <QBuffer>
#include <QTest>

QTEST_GUILESS_MAIN(TestGpgStreamWriter)

void TestGpgStreamWriter::initTestCase()
{
    QVERIFY(Crypto::init());
}

void TestGpgStreamWriter::testHasEncryptionKeyFalse()
{
    Database db;
    QBuffer buffer;
    GpgStreamWriter writer{&buffer, &db};
    QVERIFY(!writer.hasEncryptionKey());
}

void TestGpgStreamWriter::testHasEncryptionKeyTrue()
{
    Database db;
    CompositeKey key;
    key.setGpgEncryptionKey(QString{"ABC"});
    db.setKey(key);
    QBuffer buffer;
    GpgStreamWriter writer{&buffer, &db};
    QVERIFY(writer.hasEncryptionKey());
}

void TestGpgStreamWriter::testHasEncryptedStreamReturnsFalse()
{
    Database db;
    QBuffer buffer;
    GpgStreamWriter writer{&buffer, &db};
    QVERIFY(!writer.hasEncryptedStream());
}
