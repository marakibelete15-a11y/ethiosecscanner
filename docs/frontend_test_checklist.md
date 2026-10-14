# Frontend Manual Test Checklist

Run the API and serve the frontend from the same origin, then open the URLs listed in `README.md`.

- [ ] Register a new account with a valid email and password. Confirm the app returns to sign-in with an account-created message.
- [ ] Log out using the dashboard button. Confirm the login page appears and browser localStorage is empty.
- [ ] Log in with the new email and a wrong password. Confirm the API error is visible and the page does not redirect.
- [ ] Log in with the correct password. Confirm the dashboard opens and shows the validated account name and email.
- [ ] Log out, then open the dashboard URL directly. Confirm the login page appears.
- [ ] Sign in, edit the `token` value in localStorage to a fake token, and reload the dashboard. Confirm the login page appears and all localStorage credentials are cleared.
- [ ] Open the browser Network tab while signing in and visiting the dashboard. Confirm requests are limited to the expected `/api/auth/login` and `/api/auth/me` API calls; no third-party script request is made by the dashboard.