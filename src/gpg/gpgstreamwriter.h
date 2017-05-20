#ifndef GPGSTREAMWRITER_H
#define GPGSTREAMWRITER_H

#include <QIODevice>
#include "core/Database.h"
#include "streams/gpgstream.h"

class GpgStreamWriter
{
public:
    GpgStreamWriter(QIODevice* baseStream, Database* db);
    ~GpgStreamWriter();
    GpgStreamWriter(const GpgStreamWriter& that) = delete;
    GpgStreamWriter& operator=(const GpgStreamWriter& that) = delete;
    bool hasEncryptionKey();
    QIODevice* getGpgStream();
    bool isEncrypted();
    bool resetStream();
    QString getLastError();

private:
    QIODevice* m_baseStream;
    Database* m_database;
    QIODevice* m_stream;
    QString m_lastError;
};

#endif // GPGSTREAMWRITER_H
