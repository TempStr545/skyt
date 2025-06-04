import { connect } from 'cloudflare:sockets';
//本脚本通过直接访问GPT的方式验证反代有效性，人人都可以有自己的反代验证网页，直接部署，输入框输入，点击验证，搞定^_^
let 超时时间 = 5000;
let 启用网页双重验证 = false; //对于普通反代启用双重验证，默认使用了80端口，可以到相关代码研究修改，启用网页双重验证准确率更高，但是响应会变慢
export default {
  async fetch(request) {
    const { method, url } = request;
    const { pathname } = new URL(url);

    if (method === 'POST' && pathname === '/') {
      const formData = await request.formData();
      const ip = formData.get('ip');
      const result = await 验证反代IP(ip);
      return new Response(await 页面HTML(ip, `${await result.text()} （${new Date().toLocaleTimeString()}）`), {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'no-store'
        }
      });
    }

    if (method === 'GET' && pathname !== '/' && pathname.length > 1) {
      const ip = decodeURIComponent(pathname.slice(1));
      const result = await 验证反代IP(ip);
      return new Response(await result.text(), {
        headers: {
          'Content-Type': 'text/plain;charset=UTF-8',
          'Cache-Control': 'no-store'
        }
      });
    }

    return new Response(页面HTML(), {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-store'
      }
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
    align-items: center;
  }
  input[type="text"] {
    padding: 0.5em;
    font-size: 1em;
    width: 400px;
    margin-bottom: 1em;
    text-align: center;
  }
  button {
    padding: 0.5em 1em;
    font-size: 1em;
    cursor: pointer;
    width: 200px;
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
<form id="验证表单">
  <h2 style="margin-bottom: 1em; text-align: center;">PROXYIP && SOCKS5 验证工具</h2>
  <input type="text" name="ip" placeholder="输入SOCKS5或域名或IP:端口，默认443" value="${ip}" required />
  <br>
  <button type="submit">开始验证</button>
  <div class="result" id="结果显示">${结果}</div>
</form>
<div class="说明">
本工具将尝试连接GPT并判断其是否为有效的反代节点，支持IPV4+IPV6反代和带认证的 SOCKS5 代理，请输入反向代理的地址（例如：127.0.0.1:443 或 user:pass@host:port）
</div>
<script>
document.getElementById('验证表单').addEventListener('submit', async (e) => {
  e.preventDefault();
  const 表单 = e.target;
  const ip输入框 = 表单.querySelector('input[name="ip"]');
  const 结果容器 = document.getElementById('结果显示');
  结果容器.textContent = '正在验证...';
  const 表单数据 = new FormData();
  表单数据.append('ip', ip输入框.value);
  表单数据.append('nocache', Date.now()); // 防止缓存
  const 响应 = await fetch('/', {
    method: 'POST',
    body: 表单数据
  });
  const html = await 响应.text();
  const 解析器 = new DOMParser().parseFromString(html, 'text/html');
  const 新结果 = 解析器.getElementById('结果显示');
  if (新结果) {
    结果容器.textContent = 新结果.textContent;
  } else {
    结果容器.textContent = '解析失败';
  }
});
</script>
</body>
</html>`;
}
let 是SOCKS5地址 = false, SOCKS5账号;
let 访问地址 = 'chatgpt.com';
let 访问端口 = 443;
let 中转IP;
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
          throw new Error('SOCKS5账号密码错误');
        }
        const 构建账号密码包 = new Uint8Array([ 1, 账号.length, ...转换数组.encode(账号), 密码.length, ...转换数组.encode(密码) ]); //构建账号密码数据包，把字符转换为字节数组
        await 传输数据.write(构建账号密码包); //发送账号密码认证信息
        const 读取账号密码认证结果 = (await 读取数据.read()).value;
        if (读取账号密码认证结果[0] !== 0x01 || 读取账号密码认证结果[1] !== 0x00) { //检查账号密码认证结果，认证失败则退出
          throw new Error('SOCKS5账号密码错误');
        }
      }
      let 转换访问地址 = new Uint8Array( [3, 访问地址.length, ...转换数组.encode(访问地址)] );
      const 构建转换后的访问地址 = new Uint8Array([ 5, 1, 0, ...转换访问地址, 访问端口 >> 8, 访问端口 & 0xff ]); //构建转换好的地址消息
      await 传输数据.write(构建转换后的访问地址); //发送转换后的地址
      const 检查返回响应 = (await 读取数据.read()).value;
      if (检查返回响应[0] !== 0x05 || 检查返回响应[1] !== 0x00) {
        throw new Error('目标连接超时或不可达');
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
      if (启用网页双重验证) {
        TCP接口 = await 带超时连接({ hostname: 反代IP地址, port: 80 });
        传输数据 = TCP接口.writable.getWriter();
        读取数据 = TCP接口.readable.getReader();
        console.log("开始验证http");
        await 检查网页结果(地址, 传输数据, 读取数据);
        console.log("验证http通过");
        try { await TCP接口.close?.() } catch (e){ e };
      }
      TCP接口 = await 带超时连接({ hostname: 反代IP地址, port: 指定端口 });
      传输数据 = TCP接口.writable.getWriter();
      读取数据 = TCP接口.readable.getReader();
    }
    console.log("开始进行GPT握手");
    await 传输数据.write(构建GPT握手()); //发送初始握手报文，检查是否返回有效握手回应
    const 返回数据 = (await 带超时读取(读取数据)).value;
    if (返回数据[0] === 0x16 && 返回数据[1] === 0x03 && 返回数据[2] === 0x03 && 返回数据.length >= 1000) {
      for (let 尝试次数 = 1; 尝试次数 <= 5; 尝试次数++) {
        await 传输数据.write(构建GPT握手2()); //尝试发送数据交换，提升排查可靠性，但根据网络质量原因，不一定每次都能返回结果，由于TLS随机性，无法完全模拟整个数据交换过程
        const 返回数据 = (await 带超时读取(读取数据)).value;
        if (返回数据[0] === 0x17 && 返回数据[1] === 0x03 && 返回数据[2] === 0x03) {
          console.log("GPT握手成功");
          if (中转IP) return new Response(`${地址},有效,GPT响应时间: ${performance.now() - 开始时间}ms,落地地址为: ${中转IP}`);
          return new Response(`${地址},有效,GPT响应时间: ${performance.now() - 开始时间}ms`);
        }
      }
    }
    throw new Error('无法访问GPT');
  } catch (err) {
    return new Response(`${地址},无效，${err}`);
  } finally {
    try { await TCP接口.close?.() } catch {};
  }
}
function 构建GPT握手() {
  const hexStr =
    '16030107c3010007bf03030b8b6ac836ddd42f6088af62a097fb6b35b1717c0720e6358eb4206e209c07e220bc55514ff13511d59743ca08f818115628c4bdd9e6d02e7f584e672d73266fcd00205a5a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007566a6a0000000d0012001004030804040105030805050108060601fe0d00da0000010001300020ace25e9b254735ff938129f3ee1290c9431c99ae8d726257abb9e5fb14364d4c00b0dd710dca83b40a925493c18b40b4ed148ec615fd484bcfa4038e6e2b0be63663c08768f4822b50228b538fc52a8e28745753105017894179ef55b925706e7a6838b9cfa1e8ff96301d646db6df6879fe85422f246d0e89828f55a2e708eaa86881b6e3d86ea97e5697fd6750bd4d31d131ccf5873e39a80c71e4e23ddd2ec746b24733690f7c61c9a4ee3f6f25fd5c8628ff58b7e90a3fe0a394a102bc810e55df5ebeab1120a38e364bf911eb6b5e88003304ef04edeaea000100639904c02aef39e7efe4314949ccaa6c6c3856999ceda5dbb0735fa1163ef103a2094c7d0234a38ea2b35fcb1fe6a36a0d8880acc27213a27530d9c2fa5c4d1977411c3bad99169b4568450a10be9bdcbfedaa99914a6d752c0c4a3839ea3ab991e2527f08173452cb7d063bca4abbd63600dc4a21563cc75cf12207187733e14a37b8cfdea0a08b042863c53f349a2c7a16cb5387b4905a6e7e41653d56bd0dd3a47b3109e50651e519b95793a77501354ab6b37f38938c46643ddb93b438809b6b6aa8e1086940b23440c22b147bd8bca01de255d8c40183253578889055a5563da4819be65cb5868bcc575e201263b1787d5829a1430388404b24f477a19d728590e12ba207328e2a7be8246cfab540ba979102caa52e335eda577e02b58a8e8b2b2689852a4a2f538b2b601a208a10aae62c762b1c484c893e57777983084c7793adbf457051a9c52d35a73b9a7dfc5b75902a9e0fe37906b9b41e87371d00710f47bb4d4627ba65a53eb096ada31f6dd4333219925811188510465a080b1dda6c4b924e62f065b35c4af073244a3a8b17383eba7a91e1498dac5829b996c3be797bc5b7cf2339a1707840beea8dbd7c3203267ceac3556544083d380fc0790ab4b994a72b672792c5c4f190f84074f96a25ed5558f234b73b797fb1b5b65a86c24a9c192a61a9eb2b96a255a3d06968cfa529a72173c76877874267bc255b927586e683b1a829032188026c45248d467904874712bb970f2237777b933bd22ed99a2226fb58b66bc04be04b2fd5b7acc140538b75ca36a436c57098a50768d91232d102ee07cd770a8c05975ce13c0ddf478cf836afac37431e775d0ac0728bd6200ca918f5f051d439b94ba219591367c165756c3c6c071457bb7515fad452a7d6878ba2833bd81bdd025d35d159f0c46a0375c0df131569c621baec7e7e0ac3de2b368c9a9e9686750f6baca098043ea2ccc2a2823d603c1977a443c37954c145ca0719b44bc20e79472fb4517e73101250221a1cb800c35620498966dc964be1506c4a260451bdfa36409566b05c010e325b0b88e73150d50fef64b292ea33eeb9284c829c6e41cfbe8944b64c71c498b21d562d71b9bdc9aa936c175f26cac3c6b01a8c299196d7407b70bac6b625e148cf6526cae96877a2940855133e85d5b5642b82f961a54895a392a040d5db3e5992bc81e10743d352bde67c3f710bb4c72b1c68af8194231079af36e240dbfabdd9bc59efe11991526138143535c75b80383626a3725215b6290c87ce162b3454288a0b7b1494653fd0cb2c218d0b5b922904cfb3e531fe57a924b08305e61b95b26a59f0288418546fd852cdf7676bbb32cd9407c9e75359b6abe98750997753fad2694dd3a13751cbfab81f00f956d1c89aab99a853e74dd3e92121f6981b669a42a633a0ca0de00036ea307378d45ed617c11f000756db27edca91fc55bbc26c73ae5214b1a175a3086aeb946600c2abad56afdc5395742282b9d62cff453b9e44930a7cbfa080733aab1e90eb176e321650637d61e3336c85a69818858507cc5e343f519095658bab9d606b18e32fe1167b66f4a55dc84307f9c7f50a3523523192b87784d1279b51560177b4d985c7529b2484670f40cb103b62599dd22db5673e057882ca2bb680c713e6f6b6e13aa12c9b32fe4efc3b0783f6d5bfda9eb032983a377a676e3c27b122fec3af001d00203ef662f1b7740a98f49767ae4f0336e18c7f525ed7844e884f69575200cc84320010000e000c02683208687474702f312e3100230000002d00020101001b000302000200170000446900050003026832000500050100000000ff0100010000000010000e00000b636861746770742e636f6d002b0007060a0a03040303000b0002010000120000000a000c000aeaea6399001d001700187a7a000100002900eb00c600c0b87598373f86380ba4c6d41c888409608c445f9c7c7bc395e80975d6b1b98aecc66651c3941c98680a6b3227dbc778df507fbde2b03f26cc9a6667c68ea9c696782378f99c6ea7650eb52a9d4d479a9ec1fd234edcccf3316836de8425d487ee0395033547d71ac421f1844d9434b93aadfd17bffdfe8b12250f5536a842e99f44f550710fc4a1c13c04d0eb31b221a95234e1f83400d214bc8eb7a8d0a1b0d9d61e3d05c48fd9ba931fa98d05ee24d2145bf8e3af17a9b3f247b12510539d93bdda5f950021202590c04a37239dd481fa07043b69a3069c3a1aef198f98c74c136353390e2da4';
  return new Uint8Array(hexStr.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}
function 构建GPT握手2() {
  const hexStr =
    '1403030001011703030035e7fcc22ba903c71b356d1a3d6c650d49f0e9624f720eaa0adead369c564b8cf5a6cfa701abad823910287a43736c554012a8213a59170303005d9e09b06a49678638a36a91132b2abdfdabcbc9e41205b4d25300702fb568c029b8261dd174239d6de769444441ea0ad1887f336b4fa5ebc19bb525b09c6c4b81cc5a823acc588c4c56e3c0db69d47d38faf8b93aca74200d7b46ee0c99';
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
      await TCP接口.opened,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("连接超时")), 超时时间)
      ),
    ]);
    return TCP接口; // ✅ 连接成功
  } catch {
    throw new Error('目标连接超时或不可达');; // ⛔ 抛出错误由调用者处理
  }
}
function 带超时读取(读取数据) {
  return Promise.race([
    读取数据.read(),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('读取超时')), 超时时间)
    )
  ]);
}

async function 检查网页结果(地址, 传输数据, 读取数据) {
  try {
    let 响应数据 = new Uint8Array(0);
    // 构建HTTP GET请求
    const http请求 =
      "GET /cdn-cgi/trace HTTP/1.1\r\n" +
      `Host: ${地址}\r\n` +
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\r\n" +
      "Connection: close\r\n\r\n";
    // 发送HTTP请求
    await 传输数据.write(new TextEncoder().encode(http请求));
    // 读取HTTP响应
    while (true) {
      const { done: 是否结束, value: 数据块 } = await 带超时读取(读取数据);
      if (是否结束) break;
      if (数据块) {
        // 合并数据
        const 新响应数据 = new Uint8Array(响应数据.length + 数据块.length);
        新响应数据.set(响应数据);
        新响应数据.set(数据块, 响应数据.length);
        响应数据 = 新响应数据;
        const 响应文本 = new TextDecoder().decode(响应数据);
        if (响应文本.includes("\r\n\r\n") &&
            (响应文本.toLowerCase().includes("connection: close") || 响应文本.toLowerCase().includes("content-length"))) {
          break;
        }
      }
    }
    // 解析HTTP响应文本
    const 响应文本 = new TextDecoder().decode(响应数据);
    console.log("响应文本:\n" + 响应文本);
    const 状态匹配 = 响应文本.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    const 状态码 = 状态匹配 ? parseInt(状态匹配[1]) : null;
    // 判断是否为错误页（优先）
    if (响应文本.toLowerCase().includes("cf.errors.css")) {
      throw new Error(`验证Cloudflare失败（返回错误页）`);
    }
    // 检查h=域名和落地ip=指向
    if (状态码 === 200) {
      const 检查域名指向 = 响应文本.includes(`h=${地址}`);
      const ip匹配 = 响应文本.match(/ip=([^\n\r]+)/);
      const 响应IP = ip匹配 ? ip匹配[1].trim() : null;
      const 检查IP指向 = 响应IP === 地址;
      if (!检查域名指向) {
        throw new Error(`验证Cloudflare失败（域名指向错误）`);
      }
      if (!检查IP指向 && 响应IP) {
        中转IP = 响应IP;
      }
    }
    // 判断是否为成功响应
    const 长度足够 = 响应数据.length > 100;
    const 状态合法 = 状态码 === 200 || 状态码 === 400 || 状态码 === 403;
    const 包含Cloudflare = 响应文本.toLowerCase().includes("cloudflare");
    const 成功 = 长度足够 && 状态合法 && 包含Cloudflare;
    if (!成功) {
      throw new Error(`验证Cloudflare失败`);
    }
  } catch (e) {
    throw e;
  }
}
