#include "testgpgstream.h"
#include <QTest>
#include "FailDevice.h"
#include "streams/gpgstream.h"

QTEST_GUILESS_MAIN(TestGpgStream)

void TestGpgStream::testOpenReadable()
{
    Gpg gpg;
    std::vector<GpgEncryptionKey> keys;
    gpg.getAvailableSecretKeys(keys);
    m_key = keys.front();

    auto data = createTestData();
    GpgStream sut(data.get(), m_key);
    sut.open(QIODevice::ReadOnly);

    QVERIFY(sut.isReadable());
    QVERIFY(!sut.isWritable());
}

void TestGpgStream::testOpenWritable()
{
    auto data = createTestData();
    GpgStream sut(data.get(), m_key);
    sut.open(QIODevice::WriteOnly);

    QVERIFY(!sut.isReadable());
    QVERIFY(sut.isWritable());
}

void TestGpgStream::testCloseIsNotWritableOrReadable()
{
    auto data = createTestData();
    GpgStream sut(data.get(), m_key);
    sut.open(QIODevice::ReadWrite);
    sut.close();

    QVERIFY(!sut.isReadable());
    QVERIFY(!sut.isWritable());
}

void TestGpgStream::testReset()
{
    auto data = createTestData();
    GpgStream sut(data.get(), m_key);
    sut.open(QIODevice::ReadWrite);
    auto expected = sut.readAll();
    sut.reset();
    auto actual = sut.readAll();

    QCOMPARE(actual.length(), expected.length());
}

std::shared_ptr<QBuffer> TestGpgStream::createTestData()
{
    QByteArray *data = new QByteArray();
    QBuffer buffer(data);
    buffer.open(QIODevice::ReadWrite);
    GpgStream stream(&buffer, m_key);
    stream.open(QIODevice::WriteOnly);

    auto sample = QByteArray::fromStdString("test");
    stream.write(sample);
    stream.close();
    buffer.close();

    auto result = std::shared_ptr<QBuffer>(new QBuffer(data));
    result->open(QIODevice::ReadWrite);
    return result;
}
