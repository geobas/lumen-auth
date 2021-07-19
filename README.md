##  A production-ready JWT (authentication) template for Lumen to build secure APIs

### Serves routes for user registration, login, logout, refresh, reset password

---

### Set up
```
1. composer install
2. composer run-script post-root-package-install
3. artisan key:generate && artisan jwt:secret
4. Modify the generated .env accordingly
5. artisan migrate:fresh
```

### Execute unit tests
```
composer test
```