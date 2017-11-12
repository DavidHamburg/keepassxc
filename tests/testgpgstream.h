#ifndef TESTGPGSTREAM_H
#define TESTGPGSTREAM_H

#include "gpg/gpg.h"
#include "gpg/gpgencryptionkey.h"
#include <QBuffer>
#include <QObject>
#include <memory>

class TestGpgStream : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void testOpenReadable();
    void testOpenWritable();
    void testCloseIsNotWritableOrReadable();
    void testReset();

private:
    QByteArray createTestData();
    GpgEncryptionKey m_key;
};

#endif // TESTGPGSTREAM_H
