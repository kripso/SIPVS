import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ResourceLoader {
    public static File getResource(String path) {
        var resource = ResourceLoader.class.getClassLoader().getResource(path);
        if (resource == null) {
            throw new IllegalArgumentException("Path not found in resources (" + path + ")");
        }
        return new File(resource.getFile());
    }

    public static void setResource(String path, String xml) {
        Path filePath = Paths.get(path);
        try {
            Files.writeString(filePath, xml, StandardCharsets.UTF_8);

        } catch (IOException e) {
            System.out.print("Invalid Path");
        }
    }
}
