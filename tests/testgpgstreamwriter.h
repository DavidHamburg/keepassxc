#ifndef TESTGPGSTREAMWRITER_H
#define TESTGPGSTREAMWRITER_H

#include "gpg/gpgstreamwriter.h"
#include <QObject>

class TestGpgStreamWriter : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void testHasEncryptionKeyFalse();
    void testHasEncryptionKeyTrue();
    void testHasEncryptedStreamReturnsFalse();
};

#endif // TESTGPGSTREAMWRITER_H
