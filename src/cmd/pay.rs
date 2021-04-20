use crate::{
    cmd::*,
    keypair::PublicKey,
    result::{anyhow, Result},
    traits::{TxnEnvelope, TxnFee, TxnSign, B64},
};
use helium_api::{
    accounts::{self, Account},
    oracle,
};
use prettytable::Table;
use serde_json::json;
use std::str::FromStr;

#[derive(Debug, StructOpt)]
/// Send one or more payments to given addresses. Note that HNT only
/// goes to 8 decimals of precision. The payment is not submitted to
/// the system unless the '--commit' option is given.
pub struct Cmd {
    /// Address and amount of HNT to sent in <address>?amount=<amount>?memo=<memo> format.
    /// Memo parameter is optional and may be ommitted.
    #[structopt(
        long = "payee",
        short = "p",
        name = "payee?<amount>=hnt?memo=<memo>",
        required = true
    )]
    payees: Vec<Payee>,

    /// Manually set the nonce to use for the transaction
    #[structopt(long)]
    nonce: Option<u64>,

    /// Only impacts sweep payouts. Sets how many minutes in the future
    /// oracle prices should be considered for. Set to 0 for "optimistic"
    /// submission with current price.
    #[structopt(long, default_value = "120")]
    oracle_window: u64,

    /// Manually set the DC fee to pay for the transaction
    #[structopt(long)]
    fee: Option<u64>,

    /// Commit the payment to the API
    #[structopt(long)]
    commit: bool,
}

impl Cmd {
    pub async fn run(&self, opts: Opts) -> Result {
        let password = get_password(false)?;
        let wallet = load_wallet(opts.files)?;

        let client = Client::new_with_base_url(api_url(wallet.public_key.network));
        let keypair = wallet.decrypt(password.as_bytes())?;
        let account = accounts::get(&client, &keypair.public_key().to_string()).await?;

        let mut sweep_destination = None;
        let mut pay_total = 0;

        let payments: Vec<Payment> = self
            .payees
            .iter()
            .map(|p| {
                let amount = if let Amount::Hnt(amount) = p.amount {
                    let amount = u64::from(amount);
                    pay_total += amount;
                    amount
                } else if sweep_destination.is_none() {
                    sweep_destination = Some(p.address.to_vec());
                    0
                } else {
                    panic!("Cannot sweep to two addresses in the same transaction!")
                };

                Payment {
                    payee: p.address.to_vec(),
                    amount,
                    memo: p.memo,
                }
            })
            .collect();

        let mut txn = BlockchainTxnPaymentV2 {
            fee: 0,
            payments,
            payer: keypair.public_key().to_vec(),
            nonce: if let Some(nonce) = self.nonce {
                nonce
            } else {
                account.speculative_nonce + 1
            },
            signature: Vec::new(),
        };

        txn.fee = if let Some(fee) = self.fee {
            fee
        } else {
            match sweep_destination {
                // if there is no sweep destination, txn fees are simply calculated
                None => txn.txn_fee(&get_txn_fees(&client).await?)?,
                // if there is a sweep destination, the txn fees are iteratively determined
                // since the amount being swept affects the fee (protobuf encoding size changes)
                Some(sweep_destination) => {
                    let mut fee = txn.txn_fee(&get_txn_fees(&client).await?)?;
                    loop {
                        // sweep amount is remaining HNT after accounting for txn fees
                        let sweep_amount = calculate_remaining_hnt(
                            &client,
                            &account,
                            &pay_total,
                            &fee,
                            &self.oracle_window,
                        )
                        .await?;
                        // update the txn with the amount for the sweep payee
                        for payment in &mut txn.payments {
                            if payment.payee == sweep_destination {
                                payment.amount = sweep_amount;
                            }
                        }

                        // calculate fee based on the new txn size
                        let new_fee = txn.txn_fee(&get_txn_fees(&client).await?)?;

                        // if the fee matches, we are done iterating
                        if new_fee == fee {
                            break;
                        } else {
                            fee = new_fee;
                        }
                    }
                    fee
                }
            }
        };
        txn.signature = txn.sign(&keypair)?;

        let envelope = txn.in_envelope();
        let status = maybe_submit_txn(self.commit, &client, &envelope).await?;
        print_txn(&txn, &envelope, &status, opts.format)
    }
}

fn print_txn(
    txn: &BlockchainTxnPaymentV2,
    envelope: &BlockchainTxn,
    status: &Option<PendingTxnStatus>,
    format: OutputFormat,
) -> Result {
    match format {
        OutputFormat::Table => {
            let mut table = Table::new();
            table.add_row(row!["Payee", "Amount"]);
            for payment in txn.payments.clone() {
                table.add_row(row![
                    PublicKey::from_bytes(payment.payee)?.to_string(),
                    Hnt::from(payment.amount)
                ]);
            }
            print_table(&table)?;

            ptable!(
                ["Key", "Value"],
                ["Fee", txn.fee],
                ["Nonce", txn.nonce],
                ["Hash", status_str(status)]
            );

            print_footer(status)
        }
        OutputFormat::Json => {
            let mut payments = Vec::with_capacity(txn.payments.len());
            for payment in txn.payments.clone() {
                payments.push(json!({
                    "payee": PublicKey::from_bytes(payment.payee)?.to_string(),
                    "amount": Hnt::from(payment.amount),
                }))
            }
            let table = json!({
                "payments": payments,
                "fee": txn.fee,
                "nonce": txn.nonce,
                "hash": status_json(status),
                "txn": envelope.to_b64()?,
            });
            print_json(&table)
        }
    }
}

#[derive(Debug)]
pub struct Payee {
    address: PublicKey,
    amount: Amount,
    memo: u64,
}

#[derive(Debug)]
enum Amount {
    Hnt(Hnt),
    Sweep,
}

impl std::str::FromStr for Amount {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(if s == "sweep" {
            Amount::Sweep
        } else {
            Amount::Hnt(Hnt::from_str(s)?)
        })
    }
}

impl FromStr for Payee {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut split = s.split('?');

        if let Some(address) = split.next() {
            let mut amount = None;
            let mut memo = 0;

            for segment in split {
                let pos = segment
                    .find('=')
                    .ok_or_else(|| format!("invalid KEY=value: missing `=`  in `{}`", segment))?;

                let key = &segment[..pos];
                let value = &segment[pos + 1..];
                match key {
                    "amount" => amount = Some(value.parse()?),
                    "memo" => memo = u64::from_b64(value)?,
                    _ => panic!("Invalid key given"),
                }
            }
            Ok(Payee {
                address: address.parse()?,
                amount: if let Some(amount) = amount {
                    amount
                } else {
                    panic!("Pay transaction must set amount")
                },
                memo,
            })
        } else {
            panic!("Invalid command syntax. Check --help for more information")
        }
    }
}

async fn calculate_remaining_hnt(
    client: &helium_api::Client,
    account: &Account,
    pay_total: &u64,
    fee: &u64,
    oracle_window: &u64,
) -> Result<u64> {
    use rust_decimal::{prelude::*, Decimal};
    use std::time::{SystemTime, UNIX_EPOCH};

    let hnt_balance = u64::from(account.balance);
    // if account has the DCs for the charge,
    // the sweep is simply the remaining balance after payment to others
    if &account.dc_balance > fee {
        Ok(hnt_balance - pay_total)
    }
    // otherwise, we need to leave enough HNT to pay the txn fee via implicit burn
    else {
        // if window == 0, simply return the current oracle price
        let oracle_price = if *oracle_window == 0 {
            oracle::prices::current(&client).await?.price
            // else, use the oracle_window, given in minutes to select max price
        } else {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let mut oracle_prices = oracle::predictions(&client).await?;
            // filter down predictions that are not in window
            oracle_prices.retain(|prediction| {
                let prediction_time = prediction.time as u64;
                // sometimes API may be lagging real time, so if prediction is already passed
                // retain this value
                if prediction_time < now.as_secs() {
                    true
                } else {
                    // true if prediction time is within window
                    prediction_time - now.as_secs() < oracle_window * 60
                }
            });

            // take max of all predictions
            oracle_prices
                .iter()
                .fold(oracle::prices::current(&client).await?.price, |max, x| {
                    if max.get_decimal() < x.price.get_decimal() {
                        x.price
                    } else {
                        max
                    }
                })
        };
        match Decimal::from_u64(*fee) {
            Some(fee) => {
                // simple decimal division tells you the amount of HNT needed
                let mut hnt_needed = fee / oracle_price.get_decimal();
                // fee was given in DC, which is $ 10^-5
                // HNT is expresed in 10^8 bones
                // so scale by 3 to get implicit burn fee in bones
                hnt_needed.set_scale(hnt_needed.scale() - 3)?;
                // ceil rounds up for us and change into u64 for txn building
                match hnt_needed.ceil().to_u64() {
                    Some(bones_needed) => Ok(hnt_balance - pay_total - bones_needed),
                    None => Err(anyhow!("Failed to cast bones_needed into u64")),
                }
            }
            None => Err(anyhow!("Failed to parse fee as Decimal")),
        }
    }
}
