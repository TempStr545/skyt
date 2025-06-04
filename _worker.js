import { connect } from 'cloudflare:sockets';
//本脚本通过直接访问GPT的方式验证反代有效性，人人都可以有自己的反代验证网页，直接部署，输入框输入，点击验证，搞定^_^
let 超时时间 = 5000;
export default {
  async fetch(request) {
    const { method, url } = request;
    const { pathname } = new URL(url);
    if (method === 'POST' && pathname === '/') {
      const formData = await request.formData();
      const ip = formData.get('ip');
      const result = await 验证反代IP(ip);
      return new Response(await 页面HTML(ip, await result.text()), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
      });
    }
    if (method === 'GET' && pathname !== '/' && pathname.length > 1) {
      const ip = decodeURIComponent(pathname.slice(1));
      const result = await 验证反代IP(ip);
      return new Response(await result.text(), {
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' }
      });
    }
    return new Response(await 页面HTML(), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
  }
};

function 页面HTML(ip = '', 结果 = '') {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>PROXYIP && SOCKS5 验证工具</title>
  <style>
  body {
    background-color: skyblue;
    font-family: sans-serif;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100vh;
    margin: 0;
  }
  form {
    background: white;
    padding: 2em;
    border-radius: 1em;
    box-shadow: 0 0 10px rgba(0,0,0,0.1);
    display: flex;
    flex-direction: column;
    align-items: center; /* ✅ 让表单内容居中 */
  }
  input[type="text"] {
    padding: 0.5em;
    font-size: 1em;
    width: 400px; /* ✅ 增加宽度 */
    margin-bottom: 1em;
    text-align: center; /* ✅ 输入内容居中，可选 */
  }
  button {
    padding: 0.5em 1em;
    font-size: 1em;
    cursor: pointer;
    width: 200px;         /* ✅ 设置统一宽度 */
    text-align: center;
  }
  .result {
    margin-top: 1em;
    color: black;
    text-align: center;
  }
  .说明 {
    max-width: 400px;
    color: white;
    margin-top: 1.5em;
    line-height: 1.4;
    text-align: center;
    word-wrap: break-word;
  }
  </style>
</head>
<body>
<form method="POST">
  <h2 style="margin-bottom: 1em; text-align: center;">PROXYIP && SOCKS5 验证工具</h2>
  <input type="text" name="ip" placeholder="输入SOCKS5或域名或IP:端口，默认443" value="${ip}" required />
  <br>
  <button type="submit">开始验证</button>
  <div class="result">${结果}</div>
</form>
<div class="说明">
本工具将尝试连接GPT并判断其是否为有效的反代节点，支持IPV4+IPV6反代和带认证的 SOCKS5 代理，请输入反向代理的地址（例如：127.0.0.1:443 或 user:pass@host:port）
</div>
</body>
</html>`;
}
let 是SOCKS5地址 = false, SOCKS5账号;
async function 验证反代IP(地址) {
  let 开始时间 = performance.now();
  let TCP接口, 传输数据, 读取数据;
  let 原始地址 = 地址.trim();
  // 判断是否为 SOCKS5 代理格式（账号:密码@地址:端口）
  if (/^\S+:\S+@\S+:\d+$/.test(原始地址)) {
    是SOCKS5地址 = true;
    SOCKS5账号 = 原始地址
  }
  try {
    if (是SOCKS5地址) {
      let 访问地址 = 'chatgpt.com';
      let 访问端口 = 443;
      const { 账号, 密码, 地址, 端口 } = await 获取SOCKS5账号(SOCKS5账号);
      TCP接口 = await 带超时连接({ hostname: 地址, port: 端口 });
      传输数据 = TCP接口.writable.getWriter();
      读取数据 = TCP接口.readable.getReader();
      const 转换数组 = new TextEncoder(); //把文本内容转换为字节数组，如账号，密码，域名，方便与S5建立连接
      const 构建S5认证 = new Uint8Array([5, 2, 0, 2]); //构建认证信息,支持无认证和用户名/密码认证
      await 传输数据.write(构建S5认证); //发送认证信息，确认目标是否需要用户名密码认证
      const 读取认证要求 = (await 读取数据.read()).value;
      if (读取认证要求[1] === 0x02) { //检查是否需要用户名/密码认证
        if (!账号 || !密码) {
          throw new Error('SOCKS5握手失败');
        }
        const 构建账号密码包 = new Uint8Array([ 1, 账号.length, ...转换数组.encode(账号), 密码.length, ...转换数组.encode(密码) ]); //构建账号密码数据包，把字符转换为字节数组
        await 传输数据.write(构建账号密码包); //发送账号密码认证信息
        const 读取账号密码认证结果 = (await 读取数据.read()).value;
        if (读取账号密码认证结果[0] !== 0x01 || 读取账号密码认证结果[1] !== 0x00) { //检查账号密码认证结果，认证失败则退出
          throw new Error('SOCKS5握手失败');
        }
      }
      let 转换访问地址 = new Uint8Array( [3, 访问地址.length, ...转换数组.encode(访问地址)] );
      const 构建转换后的访问地址 = new Uint8Array([ 5, 1, 0, ...转换访问地址, 访问端口 >> 8, 访问端口 & 0xff ]); //构建转换好的地址消息
      await 传输数据.write(构建转换后的访问地址); //发送转换后的地址
      const 检查返回响应 = (await 读取数据.read()).value;
      if (检查返回响应[0] !== 0x05 || 检查返回响应[1] !== 0x00) {
        throw new Error('SOCKS5握手失败');
      }
    } else {
      let 反代IP地址 = 地址;
      let 指定端口 = 443;
      if (地址.includes(']')) {
        const 匹配 = 地址.match(/^\[(.+)\](?::(\d+))?$/);
        if (匹配) {
          反代IP地址 = 匹配[1];
          if (匹配[2]) 指定端口 = parseInt(匹配[2]);
        }
      } else if (地址.includes(':')) {
        const 最后冒号 = 地址.lastIndexOf(':');
        反代IP地址 = 地址.slice(0, 最后冒号);
        指定端口 = parseInt(地址.slice(最后冒号 + 1)) || 443;
      }
      TCP接口 = await 带超时连接({ hostname: 反代IP地址, port: 指定端口 });
      传输数据 = TCP接口.writable.getWriter();
      读取数据 = TCP接口.readable.getReader();
    }
    await TCP接口.opened;
  } catch {
    return new Response(`${地址},无效，目标不可达`);
  }
  await 传输数据.write(构建GPT握手());
  const 返回数据 = (await 带超时读取(读取数据)).value;
  if (返回数据[0] === 0x16 && 返回数据[1] === 0x03 && 返回数据[2] === 0x03 && 返回数据.length >= 1000) {
    await 传输数据.write(构建GPT握手2());
    const 返回数据 = (await 带超时读取(读取数据)).value;
    if (返回数据[0] === 0x17 && 返回数据[1] === 0x03 && 返回数据[2] === 0x03) {
      return new Response(`${地址},有效,GPT响应时间: ${performance.now() - 开始时间}ms`);
    }
  }
  await TCP接口.close();
  return new Response(`${地址},无效，无法访问GPT`);
}
function 构建GPT握手() {
  const hexStr =
    '16030107c3010007bf030382a2c2ff4148f77cfcdec28001b9d26487196229e13413093c260fe3d717d98d206d53939b92f39f07634bdb354627b9036313dbc61b3afd827ded06272b4237350020fafa130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000756dada00000010000e000c02683208687474702f312e31000a000c000a3a3a6399001d00170018fe0d00da0000010001580020a38efc95eb0be3337fc66a274956bfe77bd1521123ec9971cfa35cd52f09e63c00b0aff000cdfa6810cb6512b5f8a7a016a5bfc63d6e4f1d94c943445496fc3ba7a2877425a34ec830cb5a678d77ceb04f7a4ef93c03adf653e817c4ce0ab55dde50a51c063c44e2d39652e22965a2a66a236c424bd55bd1f0853006a8df3de78a6256b6f8f3bd7c032ed0432157810103da2c90346852ed993fce8b91e956686afa6e713eb5efaec57d62a2b25d49682ce59df027922d43a838a66fae5076f917018602422016c56ad1a0d770a253012bb7000b0002010000170000ff01000100003304ef04ed3a3a000100639904c08e5526d5d5ec35b9d0bf721b9b40a29eccfb863094b7243de6bb34fb85a48b3076ea3035f201dbba4e35e5533c2821ddc87008015ebd73bbd6c07ee5620b3ed9269467b3e3095e4d22c2f21911d8dabdc0b6739302c285149cb9b60babb65f692519ee55700d233ee962410f6c11800bbfdf5851c5b4068b781062cc76f5e078b4ca1e1c3113d4677378c32f87266fdbc33e1096cce5c67fd2c21800b15003ca7d54711aa983657eaa25d8d57035b9b5731c640b6a4b33e486f17b5540777d9ee29eb7055cc2da306bbc8b9f3197c519569a4714d20c8af9d0c34aa63925482c41fa0759986ae48939d6f03484f735741061109a71e70b8d727971504c3c6fb818f039a26e08a2824a25223c8a35c555b036832a07b10a46b9482960c0804b72ec5410b9782ba89dc559193abb73094549aad39d3af0bef4c34472984020e87666236bdd8141558443c626c9a0c170a1f626dc220712631770a19d194c222e42c642e4677e0a58dd7ba43d038c935c6c24007f5b217358818699605f5d6b39598126c935bdf9219ef90b85a8a9cd57818765250806b5bc88b60618a01b7650b130dbb4c6ec23b39811252a26e016800f97187e42ac042823055395dd53731c9a7db05bb93419239e142681274eeb340276c08c0a6177036b7baf1cbbd8e792ebe95a4f61cceb18cc5839877088815fbb2564703e57677076e5479a048a4ec0895ab981aeb516ba589ccf2989f9858e1526014af53a83b96e0241b9a7d939890499e3b402ef417fd54c78cab5ca73f23f56723be118377d501345ca6c76d3b78c42900106608c9482b9e49574aac34b5329cd169154d527b8e95ba1b0955938ccbe16bde3e36512ab673552a08f7ab4e6956a4c27013e468ec3d95b6755c17b4c9b8891bd7baba8ad86b854e9521a429f94e36c1a1a0ab664cc65b0577fdaa41e863ca7323e0bf9493994144a780fc2fb2ecc2c2dba54cce425886d16c8544624dd051e5946cea7e79035f7810c924dc06570b6eb414cd46342bc8e26471fafa04fa14233f490cd8495bac5796710076241f177f0db5bf3b29a88f90b39b704fcb1021da147ccf752eef0a194a14ac2d29a5a709bf7b70799614305da5974dc0ba8903ea2b81d06a926f3c3a3c8161630126f4d57afb2fa83a09006e311a7304c08a3b09e5a16aa14b110cfe390110015a57b4f1d3114ed4a379f8c6db51b4086a8a403f91bdf637736f47b4716bb1dac802e65c019e52756d054e73772a8353e472742d4d18857753353fa354b32aa4c41435ff55197dbc87dd31349675c89c8c4bb530a15e9ca3d594129bb54a7da22f7ebc529d9ab604bb55c855512008f6ca0024aac88c078a83ab946f3d881f47a47c78ca039196a5706c616a5663d90ac154a03e248463bd30b943376dbaa177b687e250c410b7a2e7bea1773755f310c6fe88362834c9554c4291a32b6be60c703e6cf9fda8a71e858b1c97f9d9c4268b47862b6097e5c416846c2f8694449118472064020ea193f076486c6bc425800efcc568027cfccb6a7b61417ec502e61e4cab6728e78e37ee8c22cfdc4b693763ec8a234b89b10167a4106cb2f4eb82f62a3223f9865c8d86e8cd0a072e89527e57e8d96c1de31cec5d6650a343b8112070a9c846404a23d84ca322229cfd9c81b34284b92d94d11c60c0fd28c869c7149092c9b71be1504ba4f9b905366fa6d001d00205bcabb725af5dbd1d2a94bbda2f42bd3cc9c987319c3a3a1bb1ba5eb568efc42002b0007066a6a030403030012000000000010000e00000b636861746770742e636f6d002d00020101001b000302000244690005000302683200050005010000000000230000000d00120010040308040401050308050501080606017a7a000100002900eb00c600c03897aba2d6fdbb12af06681cb59a06cedbbd617a8fb13048786820c714de638f26a1d73c50a375d132bfb8a16d147a1cf74ade3509f6c74d22af663ac479cf75d5a9602863c4bdc43a01c126ac8d33d129dc1ba6ff3751a38ee6de48f8b8cfb9a594f9b06f83054bf1ad8dd3973c55ff05e0ced7e60431cb35dfa01ef3f5565df7c9754480a6f2f5c806163cd9d68a62d87557eec9284ba4d2b43d4ed1d4ea5462f413a87f2d85f4b5819d7159bafa3d0bd0a567a1acc2dfe2cd468db218e7bd69a1bb4e002120543db782d82b67bf9ede9c082e54e963e5ca5cfae387f4f14b3b09f57be4f8e1';
  return new Uint8Array(hexStr.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}
function 构建GPT握手2() {
  const hexStr =
    '1403030001011703030035afb47b90f28f8c14852ca00cd704f72948ffd0dc8865f22ccd0e92ea282869e7ca3d3e4b88dae0af0e148905d81cc5199b17f091d4';
  return new Uint8Array(hexStr.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}
async function 获取SOCKS5账号(SOCKS5) {
  const [账号段, 地址段] = SOCKS5.split("@");
  const [账号, 密码] = [账号段.slice(0, 账号段.lastIndexOf(":")), 账号段.slice(账号段.lastIndexOf(":") + 1)];
  const [地址, 端口] = [地址段.slice(0, 地址段.lastIndexOf(":")), 地址段.slice(地址段.lastIndexOf(":") + 1)];
  return { 账号, 密码, 地址, 端口 };
}
async function 带超时连接({ hostname, port }) {
  const TCP接口 = connect({ hostname, port });
  try {
    await Promise.race([
      TCP接口.opened,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("连接超时")), 超时时间)
      ),
    ]);
    return TCP接口; // ✅ 连接成功
  } catch (err) {
    TCP接口.close?.(); // 确保连接关闭
    throw err; // ⛔ 抛出错误由调用者处理
  }
}
function 带超时读取(reader) {
  return new Promise(resolve => {
    const timeoutId = setTimeout(() => resolve({ done: true, value: null, 超时: true }), 超时时间);
    reader.read().then(result => {
      clearTimeout(timeoutId);
      resolve({ ...result, 超时: false });
    });
  });
}
