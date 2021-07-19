#  A build production-ready JWT (authentication) template for lumen which will help you build and secure your own APIs.

## Set up
1. `git clone https://github.com/geobas/lumen-auth.git`
2. Run `composer install`
3. Run `composer run-script post-root-package-install`
4. Modify the .env file accordingly.
5. Run `artisan key:generate`
6. Run `artisan jwt:secret`
7. Run `artisan migrate:fresh`
