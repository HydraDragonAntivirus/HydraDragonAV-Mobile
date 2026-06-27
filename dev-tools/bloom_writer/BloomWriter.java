import java.io.*;
import java.nio.charset.StandardCharsets;
import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

/**
 * CLI tool to convert a text file (one domain per line) into a Guava-compatible
 * serialized BloomFilter (.bloom) for Android assets.
 *
 * Usage:
 *   java BloomWriter <input.txt> <output.bloom> <expectedInsertions> <fpp>
 *
 * Example:
 *   java BloomWriter domains.txt output.bloom 5000000 0.01
 */
public class BloomWriter {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: java BloomWriter <input.txt> <output.bloom> [expectedInsertions] [fpp]");
            System.exit(1);
        }

        String inputPath = args[0];
        String outputPath = args[1];
        int expectedInsertions = args.length > 2 ? Integer.parseInt(args[2]) : 5000000;
        double fpp = args.length > 3 ? Double.parseDouble(args[3]) : 0.01;

        BloomFilter<CharSequence> filter = BloomFilter.create(
                Funnels.stringFunnel(StandardCharsets.UTF_8),
                expectedInsertions,
                fpp);

        long count = 0;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(inputPath), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    filter.put(line);
                    count++;
                }
            }
        }

        try (FileOutputStream fos = new FileOutputStream(outputPath)) {
            filter.writeTo(fos);
        }

        System.out.println("Wrote " + count + " entries to " + outputPath);
        System.out.println("BloomFilter size: " + new File(outputPath).length() + " bytes");
    }
}
