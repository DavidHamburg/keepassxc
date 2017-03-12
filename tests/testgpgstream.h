#ifndef TESTGPGSTREAM_H
#define TESTGPGSTREAM_H

#include <memory>
#include <QBuffer>
#include <QObject>
#include "gpg/gpgencryptionkey.h"
#include "gpg/gpg.h"

class TestGpgStream : public QObject
{
    Q_OBJECT

private slots:
    //void initTestCase();
    //void cleanupTestCase();
    void testOpenReadable();
    void testOpenWritable();
    void testCloseIsNotWritableOrReadable();
    void testReset();
private:
    std::shared_ptr<QBuffer> createTestData();
    GpgEncryptionKey m_key;
};

#endif // TESTGPGSTREAM_H
