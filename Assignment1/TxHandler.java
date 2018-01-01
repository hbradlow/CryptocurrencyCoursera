import java.util.Set;
import java.util.HashSet;
import java.security.PublicKey;
import java.util.ArrayList;

public class TxHandler {

    private UTXOPool myUtxoPool;

    public TxHandler(){
        myUtxoPool = new UTXOPool();
    }

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        myUtxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        if(tx == null){
            return false;
        }

        Set<UTXO> setUTXO = new HashSet<UTXO>();
        double totalInputValue = 0;
        double totalOutputValue = 0;

        int index = 0;
        for (Transaction.Input input : tx.getInputs()){
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            Transaction.Output claimedOutput = myUtxoPool.getTxOutput(utxo);
            byte [] data = tx.getRawDataToSign(index);

            // (1) all outputs claimed by {@code tx} are in the current UTXO pool
            if(!myUtxoPool.contains(utxo)){
                return false;
            }

            // (2) the signatures on each input of {@code tx} are valid
            if(!Crypto.verifySignature(claimedOutput.address, data, input.signature)){
                return false;
            }

            // (3) no UTXO is claimed multiple times by {@code tx}
            if(setUTXO.contains(utxo)){
                return false;
            }

            totalInputValue += claimedOutput.value;
            setUTXO.add(utxo);
            index += 1;
        }

        for (Transaction.Output output : tx.getOutputs()){

            // (4) all of {@code tx}s output values are non-negative
            if(output.value < 0){
                return false;
            }

            totalOutputValue += output.value;
        }

        // (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
        // values
        if(totalOutputValue > totalInputValue){
            return false;
        }

        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> outputTransactions = new ArrayList<Transaction>();

        for(Transaction transaction : possibleTxs){
            int index = 0;
            for(Transaction.Output output : transaction.getOutputs()){
                UTXO utxo = new UTXO(transaction.getHash(), index);
                myUtxoPool.addUTXO(utxo, output);

                index += 1;
            }
        }

        for(Transaction transaction : possibleTxs){
            if(isValidTx(transaction)){
                for(Transaction.Input input : transaction.getInputs()){
                    UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                    myUtxoPool.removeUTXO(utxo);
                }

                outputTransactions.add(transaction);
            }
            else {
                for(int index = 0; index < transaction.numOutputs(); index ++){
                    UTXO utxo = new UTXO(transaction.getHash(), index);
                    myUtxoPool.removeUTXO(utxo);
                }
            }
        }

        Transaction[] finalTransactionList = outputTransactions.toArray(new Transaction[outputTransactions.size()]);
        return finalTransactionList;
    }

}
