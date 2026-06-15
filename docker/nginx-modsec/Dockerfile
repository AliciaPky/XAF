FROM ubuntu:24.04

WORKDIR /fyp-waf

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential git ca-certificates wget curl \
    libpcre3-dev libpcre2-dev libssl-dev zlib1g zlib1g-dev \
    libyajl2 libyajl-dev libxml2 libxml2-dev pkg-config \
    libtool automake libc6-dev liblmdb-dev libjemalloc-dev \
    gcc g++ make \
    python3 python3-pip uuid-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# 1) Build ModSecurity (libmodsecurity)
RUN git clone --depth 1 -b v3/master https://github.com/owasp-modsecurity/ModSecurity.git /opt/ModSecurity \
 && cd /opt/ModSecurity \
 && git submodule update --init --recursive \
 && ./build.sh && ./configure && make -j"$(nproc)" && make install

# 2) Build modsecurity-nginx connector
RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /opt/ModSecurity-nginx

# 3) Build nginx from source with the connector
ENV NGINX_VERSION 1.24.0
RUN wget http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz \
 && tar xzf nginx-$NGINX_VERSION.tar.gz \
 && cd nginx-$NGINX_VERSION \
 && ./configure --with-compat --add-dynamic-module=/opt/ModSecurity-nginx \
    --with-http_ssl_module --with-http_v2_module --with-pcre \
 && make -j"$(nproc)" \
 && make install \
 && mkdir -p /usr/local/nginx/modules \
 && cp objs/ngx_http_modsecurity_module.so /usr/local/nginx/modules/


# 4) Create necessary directories and copy config
RUN mkdir -p /etc/nginx/conf.d /etc/modsecurity /var/log/modsecurity /usr/local/nginx/conf
COPY modsec-config/modsecurity.conf /etc/modsecurity/modsecurity.conf
COPY modsec-config/nginx.conf /usr/local/nginx/conf/nginx.conf

# 5) Create entrypoint script to start nginx
COPY modsec-config/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
CMD ["/entrypoint.sh"]
