import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class GSchreiber {
    private int[] wheelSizes = new int[] {47, 53, 59, 61, 64, 65, 67, 69, 71, 73};
    private HashMap<Integer, int[]> wheels = new HashMap<>();

    private String[] plaintext;
    private int[] ciphertext;

    private int[][] codes = {{1, 1, 0, 0, 0}, {1, 0, 0, 1, 1}, {0, 1, 1, 1, 0}, {1, 0, 0, 1, 0}, {1, 0, 0, 0, 0},
            {1, 0, 1, 1, 0}, {0, 1, 0, 1, 1}, {0, 0, 1, 0, 1}, {0, 1, 1, 0, 0}, {1, 1, 0, 1, 0}, {1, 1, 1, 1, 0},
            {0, 1, 0, 0, 1}, {0, 0, 1, 1, 1}, {0, 0, 1, 1, 0}, {0, 0, 0, 1, 1}, {0, 1, 1, 0, 1}, {1, 1, 1, 0, 1},
            {0, 1, 0, 1, 0}, {1, 0, 1, 0,0}, {0, 0, 0, 0, 1}, {1, 1, 1, 0, 0}, {0, 1, 1, 1, 1}, {1, 1, 0, 0, 1},
            {1, 0, 1, 1, 1}, {1, 0, 1, 0, 1}, {1, 0, 0, 0, 1}, {0, 0, 0, 1, 0}, {0, 1, 0, 0, 0}, {1, 1, 1, 1, 1},
            {1, 1, 0, 1, 1}, {0, 0, 1, 0, 0}, {0, 0, 0, 0, 0}};
    private String[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");
    private final int GROUP_SIZE = 5;
    private final int ALL_ONE_GROUP = 29;
    private final int ALL_ZERO_GROUP = 32;

    private HashMap<String, int[]> encoding = new HashMap<>();
    private HashMap<Integer, int[]> decoding = new HashMap<>();
    private HashMap<String, int[]> transformations = new HashMap<>();


    private ArrayList<ArrayList<Integer>> plugPermutation = new ArrayList<>();

    public GSchreiber(String[] plaintext, int[] ciphertext) {
        this.plaintext = plaintext;
        this.ciphertext = ciphertext;

        for (int i = 0; i < alphabet.length; i++)  // Plaintext to bit group translation
            encoding.put(alphabet[i], codes[i]);

        for (int i = 0; i < codes.length; i++)  // Ciphertext to bit group translation
            decoding.put(i + 1, codes[i]);  // +1 for from index conversion to cipher specification


        initializeWheels();
        initializePlugPermutations();
        initializeTransformations();
    }

    public int[] encryptTenNextChar() {
        int[] myCiphertext = new int[10];
        int[] xorGroup = new int[GROUP_SIZE];
        int[] relayGroup = new int[GROUP_SIZE];

        for (int time = 0; time < plaintext.length; time++) {
            int[] input = encoding.get(plaintext[time]);

            for (int bit = 0; bit < 2 * GROUP_SIZE; bit++) {
                int wheelSize = plugPermutation.get(bit).get(0);
                if (bit < GROUP_SIZE)
                    xorGroup[bit] = wheels.get(wheelSize)[time % wheelSize];
                else
                    relayGroup[bit - GROUP_SIZE] = wheels.get(wheelSize)[time % wheelSize];
            }

            int[] groupAfterXOR = xor(input, xorGroup);
            int[] output = relay(groupAfterXOR, relayGroup);

            if (time >= 1550)
                myCiphertext[time - 1550] = getIndex(output) + 1; // +1 for 0 to 1 index start
        }

        return myCiphertext;
    }

    public boolean testEncryption() {
        int[] myCiphertext = new int[1550];
        int[] xorGroup = new int[GROUP_SIZE];
        int[] relayGroup = new int[GROUP_SIZE];

        for (int time = 0; time < ciphertext.length; time++) {
            int[] input = encoding.get(plaintext[time]);

            for (int bit = 0; bit < 2 * GROUP_SIZE; bit++) {
                int wheelSize = plugPermutation.get(bit).get(0);
                if (bit < GROUP_SIZE)
                    xorGroup[bit] = wheels.get(wheelSize)[time % wheelSize];
                else
                    relayGroup[bit - GROUP_SIZE] = wheels.get(wheelSize)[time % wheelSize];
            }

            int[] groupAfterXOR = xor(input, xorGroup);
            int[] output = relay(groupAfterXOR, relayGroup);

            myCiphertext[time] = getIndex(output) + 1; // +1 for 0 to 1 index start
        }

        return equals(myCiphertext, ciphertext);
    }

    public void step1() {  // Use 0 and 5 weight groups in ciphertext to find 5-bit groups and first five plug permutation
        HashMap<Integer, int[]> knownGroupsBeforeXOR = new HashMap<>();

        for (int time = 0; time < ciphertext.length; time++)  // Finds all groups before xor from all zero or one groups
            if (ciphertext[time] == ALL_ZERO_GROUP || ciphertext[time] == ALL_ONE_GROUP) {
                int[] groupBeforeXOR = xor(decoding.get(ciphertext[time]), encoding.get(plaintext[time]));
                knownGroupsBeforeXOR.put(time, groupBeforeXOR);
            }

        for (int time : knownGroupsBeforeXOR.keySet())  // Removes wheel if not periodic on plug permutation
            for (int bit = 0; bit < GROUP_SIZE; bit++)
                for (int wheel : wheelSizes)
                    for (int allZeroOneGroup : knownGroupsBeforeXOR.keySet())
                        if (allZeroOneGroup % wheel == time % wheel)
                            if (knownGroupsBeforeXOR.get(time)[bit] != knownGroupsBeforeXOR.get(allZeroOneGroup)[bit])
                                plugPermutation.get(bit).remove((Object) wheel);
    }

    public void step2() {  // Restore 0-1 distribution on known wheels
        for (int time = 0; time < ciphertext.length; time++) {
            if (ciphertext[time] == ALL_ZERO_GROUP || ciphertext[time] == ALL_ONE_GROUP) {
                int[] groupBeforeXOR = xor(decoding.get(ciphertext[time]), encoding.get(plaintext[time]));

                for (int bit = 0; bit < groupBeforeXOR.length; bit++) {
                    int wheel = plugPermutation.get(bit).get(0);
                    wheels.get(wheel)[time % wheel] = groupBeforeXOR[bit];

                }
            }
        }
    }

    public void step3() {  // Use weight 1 and 4 bit groups to find last five plug permutation
        HashMap<Integer, int[]> knownGroups = findKnownGroups();

        HashMap<Integer, int[]> transformations = new HashMap<>();
        for (int time : knownGroups.keySet()) {  // Finds all transformation for the relay for weight 1 and 4
            int[] ciphertextGroup = decoding.get(ciphertext[time]);
            if (weight(ciphertextGroup) == 1 || weight(ciphertextGroup) == 4) {
                int[] xorGroup = knownGroups.get(time);
                int[] groupAfterXOR = xor(xorGroup, encoding.get(plaintext[time]));
                int[] relayGroup = this.transformations.get(uniqueTransformations(groupAfterXOR, ciphertextGroup));
                if (relayGroup != null)
                    transformations.put(time, relayGroup);
            }
        }

        for (int time : transformations.keySet())  // Tests transformations for periodicity on wheels
            for (int bit = 0; bit < GROUP_SIZE; bit++)
                for (int wheel : wheelSizes)
                    for (int relayGroup : transformations.keySet())
                        if (relayGroup % wheel == time % wheel)
                            if (transformations.get(time)[bit] != -1 && transformations.get(relayGroup)[bit] != -1)
                                if (transformations.get(time)[bit] != transformations.get(relayGroup)[bit])
                                    plugPermutation.get(bit + GROUP_SIZE).remove((Object) wheel);  // +5 offset for check bits

        for (int time : transformations.keySet()) {  // Updates 0-1 distribution with bits from transformations
            updateWheels(time, transformations.get(time));
        }
    }

    public void step4() {  // Runs through plaintext and ciphertext to find transformations on relay and updates wheels
        for (int time = 0; time < ciphertext.length; time++) {
            int[] updateGroup = new int[] {-1,-1,-1,-1,-1};

            int[] xorGroup = new int[GROUP_SIZE];
            for (int bit = 0; bit < GROUP_SIZE; bit++) {
                int wheel = plugPermutation.get(bit).get(0);
                xorGroup[bit] = wheels.get(wheel)[time % wheel];
            }

            int[] inputGroup = encoding.get(plaintext[time]);
            int[] outputGroup = decoding.get(ciphertext[time]);
            int[] groupAfterXOR = xor(inputGroup, xorGroup);

            if (weight(groupAfterXOR) == weight(outputGroup)) {
                for (int i = 0; i < groupAfterXOR.length; i++) {
                    if (groupAfterXOR[i] == -1) {
                        if (inputGroup[i] == 0) {
                            updateGroup[i] = 0;
                            xorGroup[i] = 0;
                        }
                        else if (inputGroup[i] == 1) {
                            updateGroup[i] = 1;
                            xorGroup[i] = 1;
                        }
                    }
                }
            }
            else if (zeroWeight(groupAfterXOR) == zeroWeight(outputGroup)) {
                for (int i = 0; i < groupAfterXOR.length; i++) {
                    if (groupAfterXOR[i] == -1) {
                        if (inputGroup[i] == 0) {
                            updateGroup[i] = 1;
                            xorGroup[i] = 1;
                        }
                        else if (inputGroup[i] == 1) {
                            updateGroup[i] = 0;
                            xorGroup[i] = 0;
                        }
                    }
                }
            }

            groupAfterXOR = xor(xorGroup, inputGroup);

            String transformation = "";
            if (weight(outputGroup) == weight(groupAfterXOR))
                transformation = uniqueTransformations(groupAfterXOR, outputGroup);

            updateWheels(time, updateGroup, transformation);
        }
    }

    public void step5() {  // Manually run the cipher and restore remaining values
        //manualValueDebugging();
        updateWheels(33, new int[]{0,-1,-1,-1,-1});

    }


    private void manualValueDebugging() {
        for (int time = 0; time < ciphertext.length; time++) {
            int[] input = encoding.get(plaintext[time]);
            int[] output = decoding.get(ciphertext[time]);
            int[] xorGroup = new int[5];
            int[] relayGroup = new int[5];
            for (int bit = 0; bit < 10; bit++) {
                int wheel = plugPermutation.get(bit).get(0);
                if (bit < 5)
                    xorGroup[bit] = wheels.get(wheel)[time % wheel];
                else
                    relayGroup[bit - GROUP_SIZE] = wheels.get(wheel)[time % wheel];
            }
            if (Arrays.stream(relayGroup).anyMatch(x -> x == -1)) {
                System.out.println("Time: " + time);
                System.out.println("Wheels: " + Arrays.toString(xorGroup) + " : " + Arrays.toString(relayGroup));
                System.out.println("Trans: " + Arrays.toString(xor(input, xorGroup)) + " -> "
                        + Arrays.toString(output));
            }
        }
    }

    private void updateWheels(int time, int[] relayGroup) {  // Updates bit values at wheels at instance time
        for (int bit = 0; bit < GROUP_SIZE; bit++) {
            if (relayGroup[bit] != -1) {
                int wheel = plugPermutation.get(bit + GROUP_SIZE).get(0);
                wheels.get(wheel)[time % wheel] = relayGroup[bit];
            }
        }
    }

    private void updateWheels(int time, int[] bits, String transformation) { // Updates bit values at wheels at instance time
        for (int bit = 0; bit < GROUP_SIZE; bit++) {
            if (bits[bit] != -1) {
                int wheel = plugPermutation.get(bit).get(0);
                wheels.get(wheel)[time % wheel] = bits[bit];
            }
        }

        int[] relayGroup = transformations.get(transformation);
        if (relayGroup == null)
            return;

        for (int bit = 0; bit < GROUP_SIZE; bit++) {
            if (relayGroup[bit] != -1) {
                int wheel = plugPermutation.get(bit + GROUP_SIZE).get(0);
                wheels.get(wheel)[time % wheel] = relayGroup[bit];
            }
        }
    }

    private String uniqueTransformations(int[] groupAfterXOR, int[] ciphertextGroup) {  // Trace 0 or 1 throughout the transformation and returns unique relay group
        int trace = -1;
        int groupWeight = weight(groupAfterXOR);
        if (groupWeight == 1 || groupWeight == 4)
            trace = groupWeight % 2;
        else if (groupWeight == 2 || groupWeight == 3)
            trace = (groupWeight + 1) % 2;

        String transformation = "";
        if (trace != -1) {
            for (int i = 0; i < groupAfterXOR.length; i++) {
                if (trace == groupAfterXOR[i])
                    transformation += i + ",";
            }
            for (int i = 0; i < ciphertextGroup.length; i++) {
                if (trace == ciphertextGroup[i])
                    transformation += i + ",";
            }
        }

        return transformation;
    }

    private HashMap<Integer, int[]> findKnownGroups() {  // Turns all wheels and returns complete groups
        HashMap<Integer, int[]> groupAtTime = new HashMap<>();

        for (int time = 0; time < ciphertext.length; time++) {
            int[] wheelGroup = new int[GROUP_SIZE];
            for (int bit = 0; bit < GROUP_SIZE; bit++) {
                int wheelLength = plugPermutation.get(bit).get(0);
                int[] wheel = wheels.get(wheelLength);
                wheelGroup[bit] = wheel[time % wheelLength];
            }

            if (Arrays.stream(wheelGroup).allMatch(x -> x != -1))
                groupAtTime.put(time, wheelGroup);
        }

        return groupAtTime;
    }


    private int weight(int[] group) {
        int weight = 0;
        for (int bit : group)
            if (bit == 1)
                weight++;
        return weight;
    }

    private int zeroWeight(int[] group) {
        int weight = 0;
        for (int bit : group)
            if (bit == 0)
                weight++;
        return weight;
    }

    private int getIndex(int[] group) {
        for (int i = 0; i < codes.length; i++) {
            if (equals(codes[i], group))
                return i;
        }

        return -1;
    }

    private int[] relay(int[] input, int[] checkGroup) {
        for (int bit = 4; bit >= 0; bit--) {
            if (checkGroup[4 - bit] == 0)
                input = swap(input, bit, (bit + 1) % 5);
        }

        return input;
    }

    private int[] swap(int[] group, int index, int with) {
        int copy = group[index];
        group[index] = group[with];
        group[with] = copy;
        return group;
    }


    private int[] xor(int[] a1, int[] a2) {
        if (a1.length != a2.length)
            throw new ArrayIndexOutOfBoundsException();

        int[] product = new int[a1.length];

        for (int i = 0; i < a1.length; i++) {
            if (a1[i] != -1 && a2[i] != -1)
                product[i] = a1[i] ^ a2[i];
            else
                product[i] = -1;
        }

        return product;
    }

    private boolean equals(int[] group, int[] equals) {  // Checks if all values with same index are equal
        if (group.length != equals.length)
            return false;

        for (int bit = 0; bit < group.length; bit++)
            if (group[bit] != equals[bit])
                return false;

        return true;
    }

    public void printWheels() {
        for (int wheel : wheels.keySet())
            System.out.println(wheel + ": " + Arrays.toString(wheels.get(wheel)));
    }

    public void printPlugPermutation() {
        System.out.println(plugPermutation);
    }

    private void initializeWheels() {  // Adds -1 as bit values for all wheels
        for (int wheel : wheelSizes) {
            int[] wheelArr = new int[wheel];
            for (int j = 0; j < wheel; j++) {
                wheelArr[j] = -1;
            }
            this.wheels.put(wheel, wheelArr);
        }
    }

    private void initializePlugPermutations() {  // Adds all wheels as possible periodicity on plug
        for (int i = 0; i < 10; i++)  // Possible plug permutation
            plugPermutation.add(new ArrayList<>(wheels.keySet()));
    }

    private void initializeTransformations() {
        transformations.put("0,2,", new int[] {0,0,0,1,-1});
        transformations.put("0,3,", new int[] {0,0,1,-1,-1});
        transformations.put("0,4,", new int[] {0,1,-1,-1,-1});
        transformations.put("1,0,", new int[] {-1,-1,-1,1,0});
        transformations.put("1,1,", new int[] {-1,-1,-1,1,1});
        transformations.put("1,2,", new int[] {-1,-1,-1,0,-1});
        transformations.put("2,0,", new int[] {-1,-1,1,0,0});
        transformations.put("2,1,", new int[] {-1,-1,1,0,1});
        transformations.put("2,2,", new int[] {-1,-1,1,1,-1});
        transformations.put("2,3,", new int[] {-1,-1,0,-1,-1});
        transformations.put("3,0,", new int[] {-1,1,0,0,0});
        transformations.put("3,1,", new int[] {-1,1,0,0,1});
        transformations.put("3,2,", new int[] {-1,1,0,1,-1});
        transformations.put("3,3,", new int[] {-1,1,1,-1,-1});
        transformations.put("3,4,", new int[] {-1,0,-1,-1,-1});
        transformations.put("4,2,", new int[] {1,0,0,1,-1});
        transformations.put("4,3,", new int[] {1,0,1,-1,-1});
        transformations.put("4,4,", new int[] {1,1,-1,-1,-1});

        transformations.put("0,1,0,3,", new int[] {0,0,1,1,0});
        transformations.put("0,1,0,4,", new int[] {0,1,-1,1,0});
        transformations.put("0,2,0,2,", new int[] {1,-1,1,1,1});
        transformations.put("0,2,0,4,", new int[] {0,1,1,0,0});
        transformations.put("0,3,0,2,", new int[] {1,1,0,1,1});
        transformations.put("0,3,0,3,", new int[] {1,1,1,-1,1});
        transformations.put("1,2,0,3,", new int[] {-1,-1,0,1,0});
        transformations.put("1,3,0,3,", new int[] {-1,1,1,1,0});
        transformations.put("1,3,0,4,", new int[] {-1,0,-1,1,0});
        transformations.put("1,4,1,3,", new int[] {1,0,1,1,1});
        transformations.put("1,4,1,4,", new int[] {1,1,-1,1,1});
        transformations.put("2,3,0,4,", new int[] {-1,0,1,0,0});
        transformations.put("3,4,0,2,", new int[] {0,1,0,1,1});
        transformations.put("3,4,0,3,", new int[] {0,1,1,-1,1});
        transformations.put("1,4,0,3,", new int[] {1,0,1,1,0});
        transformations.put("1,4,0,4,", new int[] {1,1,-1,1,0});
        transformations.put("1,4,2,3,", new int[] {1,0,1,0,-1});
        transformations.put("1,4,2,4,", new int[] {1,1,-1,0,-1});
        transformations.put("0,1,2,4,", new int[] {0,1,-1,0,-1});
        transformations.put("0,2,1,2,", new int[] {1,-1,1,1,0});
        transformations.put("0,2,1,4,", new int[] {0,1,1,0,1});
        transformations.put("0,2,2,4,", new int[] {0,1,1,1,-1});
        transformations.put("0,2,3,4,", new int[] {0,1,0,-1,-1});
        transformations.put("0,3,1,2,", new int[] {1,1,0,1,0});
        transformations.put("0,3,1,3,", new int[] {1,1,1,-1,0});
        transformations.put("1,2,1,3,", new int[] {-1,-1,0,1,1});
        transformations.put("1,2,2,3,", new int[] {-1,-1,0,0,-1});
        transformations.put("1,3,1,3,", new int[] {-1,1,1,1,1});
        transformations.put("1,3,1,4,", new int[] {-1,0,-1,1,1});
        transformations.put("1,3,2,3,", new int[] {-1,1,1,0,-1});
        transformations.put("1,3,2,4,", new int[] {-1,0,-1,0,-1});
        transformations.put("2,3,1,4,", new int[] {-1,0,1,0,1});
        transformations.put("2,3,2,4,", new int[] {-1,0,1,1,-1});
        transformations.put("2,3,3,4,", new int[] {-1,0,0,-1,-1});
        transformations.put("2,4,1,2,", new int[] {0,-1,1,1,0});
        transformations.put("2,4,1,4,", new int[] {1,1,0,1,-1});
        transformations.put("2,4,2,4,", new int[] {1,1,1,1,-1});
        transformations.put("2,4,3,4,", new int[] {1,1,0,-1,-1});
        transformations.put("3,4,1,2,", new int[] {0,1,0,1,0});
        transformations.put("3,4,1,3,", new int[] {0,1,1,-1,0});
        transformations.put("0,1,1,3,", new int[] {0,0,1,1,1});
        transformations.put("0,1,1,4,", new int[] {0,1,-1,1,1});
        transformations.put("0,1,2,3,", new int[] {0,0,1,0,-1});
    }  // Puts all unique transformations in path
}
