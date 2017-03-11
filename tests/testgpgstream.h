#ifndef TESTGPGSTREAM_H
#define TESTGPGSTREAM_H

#include <QBuffer>
#include <QObject>

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
    QBuffer* createTestData();
};

#endif // TESTGPGSTREAM_H
