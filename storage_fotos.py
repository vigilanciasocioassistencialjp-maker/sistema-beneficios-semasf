import os
import io
import uuid
import requests
from PIL import Image, ImageOps, UnidentifiedImageError

# =====================================================
# FOTOS DAS ATIVIDADES — armazenamento no Supabase Storage
# =====================================================
# As credenciais só são exigidas quando uma rota de /atividades é
# realmente usada (validação preguiçosa) — ao contrário de SECRET_KEY e
# CHAVE_CRIPTO, isto é uma funcionalidade opcional e não deve derrubar o
# app inteiro se ainda não foi configurada no Render.

LARGURA_MAXIMA = 1600
QUALIDADE_JPEG = 80


class StorageNaoConfigurado(Exception):
    """As variáveis de ambiente do Supabase Storage não foram definidas."""
    pass


class ImagemInvalida(Exception):
    """O arquivo enviado não é uma imagem válida."""
    pass


def _config():
    # .strip() nos 3 valores: espaço/quebra de linha grudado ao colar a
    # variável no Render é um erro comum e silencioso (o valor "existe",
    # então passa no if abaixo, mas o bucket/URL fica sutilmente errado).
    url = (os.environ.get('SUPABASE_URL') or '').strip()
    chave = (os.environ.get('SUPABASE_SERVICE_ROLE_KEY') or '').strip()
    bucket = (os.environ.get('SUPABASE_STORAGE_BUCKET') or '').strip()
    if not (url and chave and bucket):
        raise StorageNaoConfigurado(
            "Envio de fotos não configurado: defina SUPABASE_URL, "
            "SUPABASE_SERVICE_ROLE_KEY e SUPABASE_STORAGE_BUCKET no ambiente."
        )
    return url.rstrip('/'), chave, bucket


def comprimir_imagem(file_storage):
    """Recebe um FileStorage do Flask, retorna bytes de um JPEG
    redimensionado/comprimido. Levanta ImagemInvalida se não for imagem."""
    try:
        img = Image.open(file_storage.stream)
        img = ImageOps.exif_transpose(img)
        img = img.convert('RGB')
    except (UnidentifiedImageError, OSError) as e:
        raise ImagemInvalida(f"Arquivo '{file_storage.filename}' não é uma imagem válida.") from e

    if max(img.size) > LARGURA_MAXIMA:
        img.thumbnail((LARGURA_MAXIMA, LARGURA_MAXIMA), Image.LANCZOS)

    buffer = io.BytesIO()
    img.save(buffer, format='JPEG', quality=QUALIDADE_JPEG, optimize=True)
    return buffer.getvalue()


def gerar_caminho(atividade_id):
    """Gera um caminho único dentro do bucket para uma nova foto."""
    return f"atividade_{atividade_id}/{uuid.uuid4().hex}.jpg"


def upload_foto(dados_bytes, path):
    url, chave, bucket = _config()
    url_completa = f"{url}/storage/v1/object/{bucket}/{path}"
    resposta = requests.post(
        url_completa,
        headers={
            'Authorization': f'Bearer {chave}',
            'apikey': chave,
            'Content-Type': 'image/jpeg',
            'x-upsert': 'true',
        },
        data=dados_bytes,
        timeout=30,
    )
    if resposta.status_code >= 300:
        raise RuntimeError(
            f"Falha ao enviar foto para o Supabase Storage: {resposta.status_code} {resposta.text[:300]} "
            f"| bucket={bucket!r} | url={url_completa}"
        )


def excluir_foto(path):
    url, chave, bucket = _config()
    resposta = requests.delete(
        f"{url}/storage/v1/object/{bucket}/{path}",
        headers={'Authorization': f'Bearer {chave}', 'apikey': chave},
        timeout=30,
    )
    # 404 aqui só significa que o arquivo já não existia — não é um erro
    # que deva impedir a exclusão do registro no banco.
    if resposta.status_code >= 300 and resposta.status_code != 404:
        raise RuntimeError(f"Falha ao excluir foto do Supabase Storage: {resposta.status_code} {resposta.text[:300]}")


def esta_configurado():
    try:
        _config()
        return True
    except StorageNaoConfigurado:
        return False


def url_publica(path):
    url, _chave, bucket = _config()
    return f"{url}/storage/v1/object/public/{bucket}/{path}"
