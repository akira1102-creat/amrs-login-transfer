import { LOGIN_SITES, exchangeLoginTransfer, issueLoginTransfer, readVerifiedLogin } from './login-transfer.mjs?v=20261118e';

const status = document.getElementById('transferStatus');
try {
  const destination = await issueLoginTransfer(location.href,
    () => readVerifiedLogin(localStorage, 'XXGMKoasD-AJ087coIHa9i9igCK9U-hiYKaR0xXkL9I'), LOGIN_SITES, exchangeLoginTransfer);
  location.replace(destination);
} catch {
  status.textContent = '請由新站開啟登入轉接。';
}
