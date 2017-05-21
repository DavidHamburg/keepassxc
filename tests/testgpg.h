#ifndef TESTGPG_H
#define TESTGPG_H

#include "gpg/gpg.h"
#include <QObject>

class TestGpg : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void testGetAvailableSecretKeys();
    void testGetKeyById();

private:
    GpgEncryptionKey m_key;
};

#endif // TESTGPG_H
