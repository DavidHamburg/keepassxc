#include "testgpgstream.h"
#include <QTest>
#include "FailDevice.h"
#include "streams/gpgstream.h"

QTEST_GUILESS_MAIN(TestGpgStream)

void TestGpgStream::testOpenReadable()
{
    QBuffer *data = createTestData();
    GpgStream sut(data);
    sut.open(QIODevice::ReadOnly);

    QVERIFY(sut.isReadable());
    QVERIFY(!sut.isWritable());
}

void TestGpgStream::testOpenWritable()
{
    QBuffer *data = createTestData();
    GpgStream sut(data);
    sut.open(QIODevice::WriteOnly);

    QVERIFY(!sut.isReadable());
    QVERIFY(sut.isWritable());
}

void TestGpgStream::testCloseIsNotWritableOrReadable()
{
    QBuffer *data = createTestData();
    GpgStream sut(data);
    sut.open(QIODevice::ReadWrite);
    sut.close();

    QVERIFY(!sut.isReadable());
    QVERIFY(!sut.isWritable());
}

void TestGpgStream::testReset()
{
    QBuffer *data = createTestData();
    GpgStream sut(data);
    sut.open(QIODevice::ReadWrite);
    auto expected = sut.readAll();
    sut.reset();
    auto actual = sut.readAll();

    QCOMPARE(actual.length(), expected.length());
}

QBuffer* TestGpgStream::createTestData()
{
    QByteArray *data = new QByteArray();
    QBuffer buffer(data);
    buffer.open(QIODevice::ReadWrite);
    GpgStream stream(&buffer);
    stream.open(QIODevice::WriteOnly);

    auto sample = QByteArray::fromStdString("test");
    stream.write(sample);
    stream.close();
    buffer.close();
    auto result = new QBuffer(data);
    result->open(QIODevice::ReadWrite);
    return result;
}
