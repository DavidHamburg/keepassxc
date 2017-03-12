#ifndef TESTGPG_H
#define TESTGPG_H

#include <QObject>
#include "gpg/gpg.h"

class TestGpg : public QObject
{
    Q_OBJECT

private slots:
    void testGetAvailableSecretKeys();
};

#endif // TESTGPG_H
