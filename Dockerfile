FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --system --uid 10001 pwnedkeep && mkdir /data && chown pwnedkeep /data
USER pwnedkeep
VOLUME /data
ENV PWNEDKEEP_SHA1=/data/sha1.pwnd PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
ENTRYPOINT ["pwnedkeep"]
CMD ["serve"]
