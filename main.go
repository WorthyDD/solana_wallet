package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/blocto/solana-go-sdk/client"
	"github.com/blocto/solana-go-sdk/rpc"
	"github.com/blocto/solana-go-sdk/types"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/taurusgroup/frost-ed25519/pkg/eddsa"
	"github.com/tyler-smith/go-bip39"
	"net/http"
	"strconv"
	"strings"
)

func hello() {
	// create a RPC client
	c := client.NewClient(rpc.MainnetRPCEndpoint)

	// get the current running Solana version
	response, err := c.GetVersion(context.TODO())
	if err != nil {
		panic(err)
	}

	fmt.Println("version", response.SolanaCore)
}

func combinePublicKey(pubkeys []string) []byte {

	// 解码 Base64 编码的公钥
	var pubKeyBytes []byte
	for _, pubkey := range pubkeys {
		b, _ := base64.StdEncoding.DecodeString(pubkey)
		if pubKeyBytes == nil {
			pubKeyBytes = b
		} else {
			pubKeyBytes = append(pubKeyBytes, b...)
		}
	}

	combinedBytes := pubKeyBytes[:32]

	// 计算 SHA-256 哈希值
	hash := sha256.Sum256(combinedBytes)

	// 取前 32 个字节作为整合后的公钥
	finalPubKey := hash[:32]

	// 将最终的公钥转换为 Base64 字符串
	finalPubKeyBase64 := base64.StdEncoding.EncodeToString(finalPubKey)

	fmt.Println("Final Public Key (Base64):", finalPubKeyBase64)
	//return finalPubKeyBase64
	return finalPubKey
}

func newWallet(groupKey string) {

	var pk eddsa.PublicKey

	pkJson := `"` + groupKey + `"`

	var err error
	err = pk.UnmarshalJSON([]byte(pkJson))
	//err = json.Unmarshal([]byte(groupKey), &pk)
	if err != nil {
		fmt.Printf("pk unmarshal err: %v\n", err)
		return
	}

	fmt.Printf("ed25519 seed: %v\n", pk.ToEd25519())
	wallet, err := types.AccountFromSeed(pk.ToEd25519())
	if err != nil {
		fmt.Println(err)
		return
	}

	// display the wallet public and private keys
	fmt.Println("Wallet Address:", wallet.PublicKey.ToBase58())
	fmt.Println("Private Key:", wallet.PrivateKey)
}

func newWalletV2(seed ed25519.PublicKey) {

	fmt.Printf("ed25519 seed: %v\n", seed)
	wallet, err := types.AccountFromSeed(seed)
	if err != nil {
		fmt.Println(err)
		return
	}

	// display the wallet public and private keys
	fmt.Println("Wallet Address:", wallet.PublicKey.ToBase58())
	fmt.Println("Private Key:", wallet.PrivateKey)
}

func fetchBalance(address string, needAirdrop bool) {
	c := client.NewClient(rpc.DevnetRPCEndpoint)

	// request for 1 SOL airdrop using RequestAirdrop()
	if needAirdrop {
		txhash, err := c.RequestAirdrop(
			context.TODO(), // request context
			address,        // wallet address requesting airdrop
			2e9,            // amount of SOL in lamport
		)
		// check for errors
		if err != nil {
			panic(err)
		}
		fmt.Printf("txhash: %s\n", txhash)
	}

	// get balance
	balance, err := c.GetBalance(
		context.TODO(),
		address,
	)
	if err != nil {
		fmt.Printf("failed to get balance, err: %v", err)
	}
	fmt.Printf("balance: %v\n", balance)

	// get balance with sepcific commitment
	balance, err = c.GetBalanceWithConfig(
		context.TODO(),
		address,
		client.GetBalanceConfig{
			Commitment: rpc.CommitmentProcessed,
		},
	)
	if err != nil {
		fmt.Printf("failed to get balance with cfg, err: %v", err)
	}
	fmt.Printf("balance: %v\n", balance)

	// for advanced usage. fetch full rpc response
	res, err := c.RpcClient.GetBalance(
		context.TODO(),
		address,
	)
	if err != nil {
		fmt.Printf("failed to get balance via rpc client, err: %v", err)
	}
	fmt.Printf("response: %+v\n", res)
}

func createWallet(keys []string) {
	// 三个公钥的 Base64 编码
	//pubKey1Base64 := "aF/oGR6sBIuSVZ0WPX/vvX6sLsKgJAe1gKtRdjiSoE4="
	//pubKey2Base64 := "yOVFdpDkkLV0cCyGDJBP8BaJe29IFq2LbMS9khi8U20="
	//pubKey3Base64 := "DmFuLCXL4EYae+9aZ93TiyebtdGW8mFWGmjIDM967Qs="
	//keys := []string{pubKey1Base64, pubKey2Base64, pubKey3Base64}

	//pubkey := combinePublicKey(keys)

	// 解码 Base64 编码的公钥
	// 将两个密钥合并
	combinedKey := strings.Join(keys, "")

	// 使用SHA-256散列算法生成32位种子
	hasher := sha256.New()
	hasher.Write([]byte(combinedKey))
	seed := hasher.Sum(nil)

	fmt.Printf("seed: %x\n", seed)

	pk := ed25519.PublicKey(seed)

	fmt.Printf("pubkey: %v\n", pk)

	//var gkey = "sEkdzxZtXjsLM/lII7SL3Xk024XqtBiWhXbD1gZ+KwU="
	newWalletV2(pk)
}

func createWalletWithSeed(seed string) {
	pubkey := combinePublicKey([]string{seed})

	pk := ed25519.PublicKey(pubkey[:32])

	fmt.Printf("pubkey: %v\n", pk)

	//var gkey = "sEkdzxZtXjsLM/lII7SL3Xk024XqtBiWhXbD1gZ+KwU="
	newWalletV2(pk)
}

func ethWalletDemo(words string) string {
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

func fetchEthBalance(rawaddress string) float64 {

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

func ethBalanceDetect() {

	for i := 0; i < 10000; i++ {
		address := ethWalletDemo("")
		var balance = fetchEthBalance(address)
		fmt.Printf("balance: %d: %v\n", i, balance)
		if balance > 0 {
			break
		}
	}

	//var balance = fetchEthBalance("0x602d9abd5671d24026e2ca473903ff2a9a957407")
	//fmt.Printf("balance: %v\n", balance)
}

func main() {

	//hello()

	//createWallet()

	//ethWalletDemo()
	//fetchBalance("FT3SYFHYc3m8Ze1dBcoQwaGB11cfbdWTPd7oCdTuUXex")

	//ethBalanceDetect()

	//add := ethWalletDemo("shock napkin banana sister giraffe memory hill father yellow spot rubber able")
	//fetchEthBalance(add)

	//createWalletWithSeed("2CDMXcResydfmiDvhonRMrDLLkUkYtuY96L+sG9mJht7i5wZHujbdHGPRL20llTNMzLeHND/zX2dwcK9vDUyAA==")

	//keys1 := []string{
	//	"ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAid1lLMHNqQUVmcmNlWU1yaUh1NmNtUnkzQzFrY1ZHMTIrR1pXVGg5STd3WT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAieWxib2haaTV5N3NkblRyanBLYnlxeXNFd3JPRnZ6UUFCTTdJKzRkZlRqMD0iCiAgfQogfQp9",
	//	"ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAiL0gyVmM4QS9jVS9pREd5OEduenhkcDE2aS90NlVmYzdXUTV3L2VPdHZnVT0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJhTTB4K1A3d1Z0aDVLTTlmczZXTGppa1dZblpRcDhtQ0pZb1V6elcvTlVvPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiYk1zWDM3Wks5OWtYdFYyMmZ4MkZ3ZjYzMUlpMkY5eUY5K3FKKzA5MVZBaz0iCiAgfQogfQp9",
	//}
	//createWallet(keys1)
	//address1 := "4xJ3bqT3zsAqBngPoCwtYhJiZ6Ax9riBCdTHKjUUZ5gr"
	//
	//fetchBalance(address1, false)

	//keys2 := []string{
	//	"ewogIlNlY3JldHMiOiB7CiAgIjEiOiB7CiAgICJpZCI6IDEsCiAgICJzZWNyZXQiOiAiQllUaGh6aVk4UEJTTE8wMTA4MGVWRG9ySkc5bDJpd0FMMVh4ZXkrcmJRcz0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJuQlVxK041THlIaWxjdVlmZU9oVkhERFlaZWtOTXNNYXRUdm9IdUtlbFVnPSIsCiAgInNoYXJlcyI6IHsKICAgIjEiOiAiRnVUSVdUQTlJZGVNNDRiaTVtNWM0YjI2cDU2K0trQnhoY1h6MENMVzdWWT0iCiAgfQogfQp9",
	//	"ewogIlNlY3JldHMiOiB7CiAgIjIiOiB7CiAgICJpZCI6IDIsCiAgICJzZWNyZXQiOiAieUNhZEJ0TnFOZk03STVqcy9kWTcxZEk1VVpzNTV2dE9zWFNQN1pZQTlnST0iCiAgfQogfSwKICJTaGFyZXMiOiB7CiAgInQiOiAxLAogICJncm91cGtleSI6ICJuQlVxK041THlIaWxjdVlmZU9oVkhERFlaZWtOTXNNYXRUdm9IdUtlbFVnPSIsCiAgInNoYXJlcyI6IHsKICAgIjIiOiAiN0pkeXpEUXZkTEFtRUhlUk90K2pXdStVQkI3M2dQT0hnVmsxQmFWNU9VWT0iCiAgfQogfQp9",
	//}
	//createWallet(keys2)
	//address2 := "2vvzNTow58DMDZhxyp5SNTxfGXAdHehXY8nyFuRHFy4W"
	//
	//fetchBalance(address2, false)

}
