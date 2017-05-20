#include "gpgstreamwriter.h"
#include "gpg/gpg.h"

GpgStreamWriter::GpgStreamWriter(QIODevice* baseStream, Database* db)
    : m_baseStream(baseStream)
    , m_database(db)
    , m_stream(nullptr)
{
}

GpgStreamWriter::~GpgStreamWriter()
{
    delete m_stream;
}

bool GpgStreamWriter::hasEncryptionKey()
{
    return !m_database->key().gpgEncryptionKeyId().isNull();
}

QIODevice* GpgStreamWriter::getGpgStream()
{
    if (!m_stream) {
        Gpg gpg;
        auto key = gpg.getKeyById(m_database->key().gpgEncryptionKeyId());
        m_stream = new GpgStream{m_baseStream, key};
        if (!m_stream->open(QIODevice::WriteOnly)) {
            m_lastError = m_stream->errorString();
            return nullptr; // review
        }
    }
    return m_stream;
}

bool GpgStreamWriter::isEncrypted()
{
    return m_stream != nullptr;
}

bool GpgStreamWriter::resetStream()
{
    bool result = true;
    if (m_stream != nullptr) {
        result = m_stream->reset();
        if (!result) {
            m_lastError = m_stream->errorString();
        }
    }

    return result;
}

QString GpgStreamWriter::getLastError()
{
    return m_lastError;
}
