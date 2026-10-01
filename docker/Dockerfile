FROM composer:2 AS composer

FROM php:8.3-fpm-alpine AS app
COPY --from=composer /usr/bin/composer /usr/bin/composer

# Install required dependencies
RUN apk --no-cache add \
    su-exec \
    postgresql-dev \
    libpng-dev \
    zlib-dev \
    oniguruma-dev \
    libzip-dev \
    zip \
    unzip \
    autoconf \
    gcc \
    g++ \
    make \
    bash \
    postgresql-client \
    linux-headers \
    libtool \
    nodejs \
    npm

# Add extra PHP dependencies
RUN docker-php-ext-install pdo pgsql pdo_pgsql gd bcmath zip exif pcntl \
    && pecl install redis \
    && docker-php-ext-enable redis \
    && docker-php-ext-configure pcntl --enable-pcntl

WORKDIR /usr/share/caddy/html/
COPY . .

# Install dependencies with composer
# NOTE: intentionally NOT using --no-dev here. Build-time artisan commands
# (package:discover, the wayfinder vite plugin) fully boot the app, so any
# require-dev package with a service provider must be present in vendor or
# the boot fails with "Class ... not found". Dev packages here (boost, pail,
# faker, etc.) don't do anything at runtime in production, so shipping them
# in vendor is a harmless trade-off vs. chasing missing providers one by one.
RUN composer validate --strict \
  && composer install \
  --no-interaction \
  --no-progress \
  --no-scripts \
  && composer clear-cache

# Drop any stale auto-discovery cache copied in via `COPY . .` (it may still
# reference dev-only providers like laravel/boost from a local composer install),
# then regenerate it fresh against the --no-dev vendor install
RUN rm -f bootstrap/cache/packages.php bootstrap/cache/services.php \
  && php artisan package:discover --ansi

# Install NPM dependencies and build frontend assets
RUN npm install \
  && npm run build \
  && rm -rf node_modules \
  && npm cache clean --force

# Set permissions and prepare Laravel
RUN chown -R www-data:www-data /usr/share/caddy/html/storage \
  && chown -R www-data:www-data /usr/share/caddy/html/bootstrap/cache \
  && chmod -R 775 /usr/share/caddy/html/storage \
  && chmod -R 775 /usr/share/caddy/html/bootstrap/cache

COPY ./docker/php-fpm-entrypoint /usr/local/bin/php-entrypoint

RUN chmod a+x /usr/local/bin/*

FROM app

ENTRYPOINT ["/usr/local/bin/php-entrypoint"]

CMD ["php-fpm"]
