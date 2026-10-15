# Frontend Manual Test Checklist

Run the API and serve the frontend from the same origin, then open the URLs listed in `README.md`.

- [ ] Register a new account with a valid email and password. Confirm the app returns to sign-in with an account-created message.
- [ ] Log out using the dashboard button. Confirm the login page appears and browser localStorage is empty.
- [ ] Log in with the new email and a wrong password. Confirm the API error is visible and the page does not redirect.
- [ ] Log in with the correct password. Confirm the dashboard opens and shows the validated account name and email.
- [ ] Log out, then open the dashboard URL directly. Confirm the login page appears.
- [ ] Sign in, edit the `token` value in localStorage to a fake token, and reload the dashboard. Confirm the login page appears and all localStorage credentials are cleared.
- [ ] Open the browser Network tab while signing in and visiting the dashboard. Confirm requests are limited to the expected `/api/auth/login` and `/api/auth/me` API calls; no third-party script request is made by the dashboard.

## Target Verification (`/static/pages/target_verify.html`)

- [ ] Open target verification while signed out. Confirm the protected-page auth check redirects to sign-in; sign in and return to the page.
- [ ] Confirm the legal authorization notice is visible above the add-target form at desktop and phone widths.
- [ ] Add a valid HTTPS URL using each method (meta tag, DNS TXT, verification file). Confirm the target appears with its method, unverified badge, and timestamps, and the new target's instructions open automatically.
- [ ] Confirm the proof area shows the token and only the selected method's proof fields. Use each Copy button and verify the copied value; repeat with clipboard permissions unavailable to exercise the fallback.
- [ ] Select an existing target. Confirm the page fetches its detail endpoint and displays the method-correct proof and token.
- [ ] Submit a malformed URL, a duplicate URL, and private, loopback, and metadata-service addresses. Confirm the server's error message is shown without clearing the form or navigating away.
- [ ] Publish the indicated proof at the target, select Verify now, and confirm the button disables with a visible pending state. Confirm the badge becomes Verified only when the response has `is_verified: true`.
- [ ] Attempt verification without publishing the proof. Confirm the server failure reason and updated last-checked time are shown, with no success message or verified badge.
- [ ] Delete a target and cancel once; confirm it remains. Delete again and confirm the prompt warns that scans and findings will be deleted, then confirm the target is removed and the list refreshes.
- [ ] Confirm a verified target has a Scan this target link to `new_scan.html?target=<id>`.
- [ ] With no targets, confirm the friendly empty state. Confirm API/network errors appear visibly and the Refresh action retries the list.
- [ ] Confirm no inline scripts, inline event handlers, `innerHTML`, or external scripts are used on this page.