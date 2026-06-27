import java.io.*;
import java.nio.charset.StandardCharsets;
import com.google.common.hash.BloomFilter;
import com.google.common.hash.Funnels;

public class BloomVerify {
    public static void main(String[] args) throws Exception {
        BloomFilter<CharSequence> f = BloomFilter.readFrom(
            new FileInputStream(args[0]),
            Funnels.stringFunnel(StandardCharsets.UTF_8));

        System.out.println("zzzxadsa.top: " + f.mightContain("zzzxadsa.top"));
        System.out.println("google.com: " + f.mightContain("google.com"));
        System.out.println("example.com: " + f.mightContain("example.com"));

        BufferedReader reader = new BufferedReader(new InputStreamReader(
            new FileInputStream(args[1]), StandardCharsets.UTF_8));
        int tested = 0; int matched = 0;
        String line;
        while ((line = reader.readLine()) != null && tested < 10000) {
            line = line.trim();
            if (!line.isEmpty()) {
                if (f.mightContain(line)) matched++;
                tested++;
            }
        }
        reader.close();
        System.out.println("\nVerified " + tested + " entries: " + matched + " matched (expect all)");
    }
}
