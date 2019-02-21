package com.wizzardo.spring;

import com.wizzardo.tools.io.FileTools;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class MultipartFileWrapper implements MultipartFile {

    public final File file;
    public final String filename;
    public final String parameter;

    public MultipartFileWrapper(File file, String filename, String parameter) {
        this.file = file;
        this.filename = filename;
        this.parameter = parameter;
    }

    @Override
    public String getName() {
        return parameter;
    }

    @Override
    public String getOriginalFilename() {
        return filename;
    }

    @Override
    public String getContentType() {
        return null;
    }

    @Override
    public boolean isEmpty() {
        return getSize() == 0;
    }

    @Override
    public long getSize() {
        return file.length();
    }

    @Override
    public byte[] getBytes() throws IOException {
        return FileTools.bytes(file);
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new FileInputStream(file);
    }

    @Override
    public void transferTo(File dest) throws IOException, IllegalStateException {
        try (InputStream in = getInputStream()) {
            FileTools.bytes(dest, in);
        }
    }
}
