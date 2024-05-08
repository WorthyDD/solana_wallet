package spider

import (
	"bytes"
	"encoding/json"
	"fmt"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
	"net/http"
	"strconv"
)

func EthWalletDemo(words string) string {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		fmt.Println(err)
	}

	mnemonic, _ := bip39.NewMnemonic(entropy)
	if len(words) > 0 {
		mnemonic = words
	}

	//var mnemonic = "pepper hair process town say voyage exhibit over carry property follow define"
	fmt.Println("mnemonic:", mnemonic)
	seed := bip39.NewSeed(mnemonic, "") //这里可以选择传入指定密码或者空字符串，不同密码生成的助记词不同

	wallet, err := hdwallet.NewFromSeed(seed)
	if err != nil {
		fmt.Println(err)
	}

	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0") //最后一位是同一个助记词的地址id，从0开始，相同助记词可以生产无限个地址
	account, err := wallet.Derive(path, false)
	if err != nil {
		fmt.Println(err)
	}

	address := account.Address.Hex()
	privateKey, _ := wallet.PrivateKeyHex(account)
	publicKey, _ := wallet.PublicKeyHex(account)

	fmt.Println("address0:", address)      // id为0的钱包地址
	fmt.Println("privateKey:", privateKey) // 私钥
	fmt.Println("publicKey:", publicKey)   // 公钥

	//path = hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/1") //生成id为1的钱包地址
	//account, err = wallet.Derive(path, false)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//
	//fmt.Println("address1:", account.Address.Hex())

	return address
}

func FetchEthBalance(rawaddress string) float64 {

	infuraKey := "8f3852a5e42d473ab1dea53190f2335d"
	//infuraSec := "EWYJRVoe2Ol9WDX0+N4zlw8DVpy0A0Yr3HYjVN8mFPdwGWL2YIeQSQ"

	url := "https://mainnet.infura.io/v3/" + infuraKey
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getBalance",
		"params":  []interface{}{rawaddress, "latest"},
		"id":      1,
	}

	// 将数据转换为 JSON 格式
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("JSON encoding error:", err)
		return 0
	}

	// 发送 POST 请求
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("POST request error:", err)
		return 0
	}
	defer resp.Body.Close()

	// 读取响应的内容
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Println("Failed to decode response:", err)
		return 0
	}

	// 提取余额并转换为十进制整数
	balanceHex := result["result"].(string)
	balanceInt, err := strconv.ParseInt(balanceHex[2:], 16, 64)
	if err != nil {
		fmt.Println("Failed to parse balance:", err)
		return 0
	}

	// 打印余额
	fmt.Println("Balance:", result)
	return float64(balanceInt) / 1000000000000000000

	// 1. 连接到以太坊节点
	//client, err := ethclient.Dial("https://mainnet.infura.io/v3/your-infura-project-id")
	//if err != nil {
	//	fmt.Println(err)
	//}
	//
	//// 2. 要查询的地址
	//address := common.HexToAddress(rawaddress)
	//
	//// 3. 查询余额
	//balance, err := client.BalanceAt(context.Background(), address, nil)
	//if err != nil {
	//	fmt.Println(err)
	//}
	//
	//// 4. 打印余额
	//fmt.Println("ETH Balance:", balance) // 以 wei 为单位的余额

	// 可以选择将余额转换为以太或其他单位
	// ethBalance := weiToEth(balance)
	// fmt.Println("Balance (ETH):", ethBalance)
}
