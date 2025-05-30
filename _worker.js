import { connect } from 'cloudflare:sockets';
//本脚本通过直接访问GPT的方式验证反代有效性，人人都可以有自己的反代验证网页，直接部署，输入框输入，点击验证，搞定^_^
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
  <title>PROXYIP 验证工具</title>
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
  </style>
</head>
<body>
<form method="POST">
  <h2 style="margin-bottom: 1em; text-align: center;">PROXYIP 验证工具</h2>
  <input type="text" name="ip" placeholder="输入域名或IP加端口，默认443" value="${ip}" required />
  <br>
  <button type="submit">开始验证</button>
  <div class="result">${结果}</div>
</form>
</body>
</html>`;
}
async function 验证反代IP(地址) {
  let TCP接口;
    let [反代IP地址, 指定端口 = 443] = 地址.split(':');
      try {
        TCP接口 = await 带超时连接({ hostname: 反代IP地址, port: 指定端口 }, 1000);
      } catch {
        return new Response(`${地址}无效`);
      }
      const 传输数据 = TCP接口.writable.getWriter();
      const 读取数据 = TCP接口.readable.getReader();
      let 开始时间 = performance.now();
      传输数据.write(构建GPT握手());
      const { value: 返回数据 } = await 带超时读取(读取数据, 1000);
      if (返回数据[0] === 0x16) {
        return new Response(`${反代IP地址}:${指定端口}有效-GPT响应时间: ${performance.now() - 开始时间}ms`);
      }
      读取数据.cancel();
      await new Promise(resolve => setTimeout(resolve, 100));
      TCP接口.close();
      await new Promise(resolve => setTimeout(resolve, 100));
  return new Response(`${地址}无效`);
}
function 构建GPT握手() {
  const hexStr =
    '16030107a30100079f0303af1f4d78be2002cf63e8c727224cf1ee4a8ac89a0ad04bc54cbed5cd7c830880203d8326ae1d1d076ec749df65de6d21dec7371c589056c0a548e31624e121001e0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010007361a1a0000000a000c000acaca11ec001d00170018fe0d00ba0000010001fc00206a2fb0535a0a5e565c8a61dcb381bab5636f1502bbd09fe491c66a2d175095370090dd4d770fc5e14f4a0e13cfd919a532d04c62eb4a53f67b1375bf237538cea180470d942bdde74611afe80d70ad25afb1d5f02b2b4eed784bc2420c759a742885f6ca982b25d0fdd7d8f618b7f7bc10172f61d446d8f8a6766f3587abbae805b8ef40fcb819194ac49e91c6c3762775f8dc269b82a21ddccc9f6f43be62323147b411475e47ea2c4efe52ef2cef5c7b32000d00120010040308040401050308050501080606010010000e000c02683208687474702f312e31000b0002010000050005010000000044cd00050003026832001b00030200020017000000230000002d000201010012000000000010000e00000b636861746770742e636f6dff01000100002b0007061a1a03040303003304ef04edcaca00010011ec04c05eac5510812e46c13826d28279b13ce62b6464e01ae1bb6d49640e57fb3191c656c4b0167c246930699d4f467c19d60dacaa86933a49e5c97390c3249db33c1aa59f47205701419461569cb01a22b4378f5f3bb21d952700f250a6156841f2cc952c75517a481112653400913f9ab58982a3f2d0010aba5ae99a2d69f6617a4220cd616de58ccbf5d10c5c68150152b60e2797521573b10413cb7a3aab25409d426a5b64a9f3134e01dc0dd0fc1a650c7aafec00ca4b4dddb64c402252c1c69ca347bb7e49b52b214a7768657a808419173bcbea8aa5a8721f17c82bc6636189b9ee7921faa76103695a638585fe678bcbb8725831900f808863a74c52a1b2caf61f1dec4a9016261c96720c221f45546ce0e93af3276dd090572db778a865a07189ae4f1a64c6dbaa25a5b71316025bd13a6012994257929d199a7d90a59285c75bd4727a8c93484465d62379cd110170073aad2a3fd947087634574315c09a7ccb60c301d59a7c37a330253a994a6857b8556ce0ac3cda4c6fe3855502f344c0c8160313a3732bce289b6bda207301e7b318277331578f370ccbcd3730890b552373afeb162c0cb59790f79559123b2d437308061608a704626233d9f73d18826e27f1c00157b792460eda9b35d48b4515a17c6125bdb96b114503c99e7043b112a398888318b956a012797c8a039a51147b8a58071793c14a3611fb0424e865f48a61cac7c43088c634161cea089921d229e1a370effc5eff2215197541394854a201a6ebf74942226573bb95710454bd27a52d444690837d04611b676269873c50c3406a79077e6606478a841f96f7b076a2230fd34f3eea301b77bf00750c28357a9df5b04f192b9c0bbf4f71891f1842482856b021280143ae74356c5e6a8e3273893086a90daa7a92426d8c370a45e3906994b8fa7a57d66b503745521e40948e83641de2a751b4a836da54f2da413074c3d856c954250b5c8332f1761e616437e527c0840bc57d522529b9259ccac34d7a3888f0aade0a66c392458cc1a698443052413217d29fbb9a1124797638d76100f82807934d58f30fcff33197fc171cfa3b0daa7f729591b1d7389ad476fde2328af74effd946265b3b81fa33066923db476f71babac30b590e05a7ba2b22f86925abca7ef8058c2481278dd9a240c8816bba6b5e6603e30670dffa7e6e3b995b0b18ec404614198a43a07897d84b439878d179c7d6895ac3f42ecb7998d4491060d2b8a5316110830c3f20a3d9a488a85976545917124c1eb6eb7314ea9696712b7bcab1cfd2b66e5a85106b2f651ab4b8a145e18ac41f39a394da9f327c5c92d4a297a0c94d1b8dcc3b111a700ac8d81c45f983ca029fd2887ad4113c7a23badf807c6d0068b4fa7148402aae15cc55971b57669a4840a22301caaec392a6ea6d46dab63890594d41545ebc2267297e3f4146073814bb3239b3e566684293b9732894193e71f3b388228641bb8be6f5847abb9072d269cb40b353b6aa3259ccb7e438d6a37ffa8cc1b7e4911575c41501321769900d19792aa3cfbe58b0aaf91c91d3b63900697279ad6c1aa44897a07d937e0d5826c24439420ca5d8a63630655ce9161e58d286fc885fcd9b19d096080225d16c89939a24aa1e98632d497b5604073b13f65bdfddc1de4b40d2a829b0521010c5f0f241b1ccc759049579db79983434fac2748829b33f001d0020a8e86c9d3958e0257c867e59c8082238a1ea0a9f2cac9e41f9b3cb0294f34b484a4a000100002900eb00c600c0afc8dade37ae62fa550c8aa50660d8e73585636748040b8e01d67161878276b1ec1ee2aff7614889bb6a36d2bdf9ca097ff6d7bf05c4de1d65c2b8db641f1c8dfbd59c9f7e0fed0b8e0394567eda55173d198e9ca40883b291ab4cada1a91ca8306ca1c37e047ebfe12b95164219b06a24711c2182f5e37374d43c668d45a3ca05eda90e90e510e628b4cfa7ae880502dae9a70a8eced26ad4b3c2f05d77f136cfaa622e40eb084dd3eb52e23a9aeff6ae9018100af38acfd1f6ce5d8c53c4a61c547258002120fe93e5c7a5c9c1a04bf06858c4dd52b01875844e15582dd566d03f41133183a0';
  return new Uint8Array(hexStr.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}
async function 带超时连接({ hostname, port }, 超时时间) {
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
function 带超时读取(reader, 超时) {
  return new Promise(resolve => {
    const timeoutId = setTimeout(() => resolve({ done: true, value: null, 超时: true }), 超时);
    reader.read().then(result => {
      clearTimeout(timeoutId);
      resolve({ ...result, 超时: false });
    });
  });
}
