#include "testgpgstream.h"
#include "FailDevice.h"
#include "streams/gpgstream.h"
#include <QTest>

QTEST_GUILESS_MAIN(TestGpgStream)

void TestGpgStream::initTestCase()
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

void TestGpgStream::testOpenReadable()
{
    auto data = createTestData();
    QBuffer buffer(&data);
    buffer.open(QIODevice::ReadWrite);
    GpgStream sut(&buffer, m_key);
    sut.open(QIODevice::ReadOnly);

    QVERIFY(sut.isReadable());
    QVERIFY(!sut.isWritable());
}

void TestGpgStream::testOpenWritable()
{
    auto data = createTestData();
    QBuffer buffer(&data);
    buffer.open(QIODevice::ReadWrite);
    GpgStream sut(&buffer, m_key);
    sut.open(QIODevice::WriteOnly);

    QVERIFY(!sut.isReadable());
    QVERIFY(sut.isWritable());
}

void TestGpgStream::testCloseIsNotWritableOrReadable()
{
    auto data = createTestData();
    QBuffer buffer(&data);
    buffer.open(QIODevice::ReadWrite);
    GpgStream sut(&buffer, m_key);
    sut.open(QIODevice::ReadWrite);
    sut.close();

    QVERIFY(!sut.isReadable());
    QVERIFY(!sut.isWritable());
}

void TestGpgStream::testReset()
{
    auto data = createTestData();
    QBuffer buffer(&data);
    buffer.open(QIODevice::ReadWrite);
    GpgStream sut(&buffer, m_key);
    sut.open(QIODevice::ReadWrite);
    auto expected = sut.readAll();
    sut.reset();
    auto actual = sut.readAll();

    QCOMPARE(actual.length(), expected.length());
}

QByteArray TestGpgStream::createTestData()
{
    QByteArray data{};
    QBuffer buffer(&data);
    buffer.open(QIODevice::ReadWrite);
    GpgStream stream(&buffer, m_key);
    stream.open(QIODevice::WriteOnly);

    auto sample = QByteArray::fromStdString("test");
    stream.write(sample);
    stream.close();
    buffer.close();

    return data;
}
